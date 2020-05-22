/*
 * $Id$
 */
#include "db_pg.hxx"
#include "edgepq.h"
#include "global.h"
#include "log.h"
#include "ttn_tools.hxx"

#include <climits>
#include <cstddef>
#include <iostream>
#include <libpq-fe.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace titan_v3::globals;
using namespace titan_v3::tools;
// http://www.postgresql.org/docs/8.2/static/libpq.html

void PGresult_reseter::operator()(PGresult* ptr) const noexcept{
    if (ptr) txpq_reset(ptr);
}

struct t_checkError{
   inline void operator()(PGresult* const res, const std::string & errorMsg,const bool auto_close_if_no_error=true)const{
      if (res){
         ExecStatusType stat=PGRES_EMPTY_QUERY;
         if (((stat=::PQresultStatus(res))==PGRES_COMMAND_OK) ||  (stat==PGRES_TUPLES_OK)){
            if (auto_close_if_no_error) ::txpq_reset(res);
            return;
         }
         ::txpq_reset(res);
      }

      if (errorMsg.size() && ::strcasestr(errorMsg.c_str(), "violates") != NULL && ::strcasestr(errorMsg.c_str(), "constraint") != NULL)
         throw errors::constraint_violation_error();
      else
         throw errors::execution_error(errorMsg);
   }
};

struct t_checkData{
   inline bool operator()(PGresult* const res,const bool auto_close_on_error=true) const {
      if (::txpq_row_count(res)) return true;
      if (auto_close_on_error) ::txpq_reset(res);
      throw errors::no_data_error();
   }
};

static t_checkError checkError;
static t_checkData checkData;

void PGconn_deleter::operator()(PGconn* ptr) const{
   if (ptr) (void)pq_conn_close(ptr);
}

void PgDatabaseQuery::prepareBindParams_()
{
   mBindParamsValues.assign(mBindParams.size(),NULL);
   size_t idx = 0;
   const std::vector<bool> & mBindParamsIsNULL_=mBindParamsIsNULL;
   std::vector<char*> & mBindParamsValues_=mBindParamsValues;   
   for ( auto & bParam : mBindParams ){

      if ( !mBindParamsIsNULL_[idx] ) {

         mBindParamsValues_[idx]=const_cast<char*>(bParam.c_str());
      }

      ++idx;
   }
}

bool PgDatabaseQuery::setBindParam(const size_t pos){
   if (pos){
      std::lock_guard<std::mutex> lock{mBindParams_lock};
      checkBindParamsSize_(pos-1);
      mBindParams[pos-1]=std::string{};
      mBindParamsIsNULL[pos-1] = true;
      prepareBindParams_();
      return true;
   }
   throw tools::errors::low_position_error();
   //it is safe to remove this as long as code is compiled with support for the throwable exceptions
   //return false;
}

bool PgDatabaseQuery::setBindParam(const size_t pos, std::ostringstream& o_){
   if (pos){
      std::lock_guard<std::mutex> lock{mBindParams_lock};
      checkBindParamsSize_(pos-1);
      mBindParams[pos-1]={o_.str()};
      mBindParamsIsNULL[pos-1] = false;
      prepareBindParams_();
      return true;
   }
   throw tools::errors::low_position_error();
   //it is safe to remove this as long as code is compiled with support for the throwable exceptions
   //return false;
}

bool PgDatabaseQuery::setBindParam(const size_t pos, functors::tos && o_){
   if (pos){
      std::lock_guard<std::mutex> lock{mBindParams_lock};
      checkBindParamsSize_(pos-1);      
      mBindParams[pos-1]=std::move(o_);
      mBindParamsIsNULL[pos-1] = false;
      prepareBindParams_();
      return true;
   }
   throw tools::errors::low_position_error();
   //it is safe to remove this as long as code is compiled with support for the throwable exceptions
   //return false;
}

bool PgDatabaseQuery::execute(PGresult ** out,const bool throw_exception_if_no_data){
   if (out && (*out=this->execute_query_())){
      (void)(throw_exception_if_no_data && checkData(*out));
      return true;
   }
   throw tools::errors::execution_error("execute with RS");
   //it is safe to remove this as long as code is compiled with support for the throwable exceptions
   //return false;
}

bool PgDatabaseQuery::execute(   t_query_lamda lmbd,
                                 const bool throw_exception_if_no_data  )
{
   PGresult * r_{};
   try{

      if ( execute(&r_,throw_exception_if_no_data) ) {

         lmbd(r_);

         this->closeRS(r_);

         return true;
      }

   }catch (...){

      this->closeRS(r_);
      throw;
   }
      
   return false;
}

void PgDatabaseQuery::closeRS(PGresult* rs_){
   if (rs_) ::txpq_reset(rs_);
}

PGresult* PgDatabaseQuery::execute_query_(const bool data_expected){

   // TODO: OPTIMISE: PQexecPrepared()
   std::lock_guard<std::mutex> lock{mBindParams_lock};
   /**
    * Use local vector<char*> instead of dynamically allocated memory/array
    * because in case of exceptions it will cause a memory leak (array won't be deleted)
    */
   if (this->mDatabase.isOpen() || this->mDatabase.reOpen()){
      PGconn * const dbcon=this->mDatabase.mDatabase.get();
      const char * const qstr=this->mQuery.c_str();
      if (dbcon && qstr){
         const auto BindParamsValuesSize=static_cast<int>(mBindParamsValues.size());
         if (PGresult* const res =(!BindParamsValuesSize
            ? ::pq_get_rset_no_error(dbcon,qstr)
            : ::pq_get_rset_with_params(dbcon,qstr,BindParamsValuesSize,mBindParamsValues.data()))){
               const char * const emsg=mDatabase.errorMsg();
               checkError(res, (emsg?std::string{emsg}:std::string{}),!data_expected);
               if (data_expected) return (res);
               //res is already closed at this stage
               return (NULL);
         }
      }
   }
   throw tools::errors::db_handler_error();
}

// TODO: OPTIMISE: postgres would be faster if we had a version that can specify types of params
std::string PgDatabaseQuery::convertPlaceholders_(){   
   
   size_t placeholderNumber = 1;
   strings_t out_{};
   const size_t parplaces=titan_v3::tools::split(out_,raw_query,"?")-1;
   if (!parplaces) return {raw_query};
   std::string convertedSql{};
   for(auto part:out_){
      convertedSql+=part;
      if (!(placeholderNumber>parplaces)){
         convertedSql+='$';
         convertedSql+=tools::functors::tos{placeholderNumber++};
   }
   }
   return convertedSql;
}

bool PgDatabaseQuery::prepare(std::string raw_query_,const bool auto_reset){
   TXDEBLOG(::titax_log(LOG_DEBUG, "PgDatabaseQuery::prepare()\n"));
   if (auto_reset) (void)this->reset();
   raw_query=std::move(raw_query_);
   return this->reprepare();
    // TODO: OPTIMISE: PQprepare() in V8.x
}

bool PgDatabaseQuery::reset(){
   return finish_();
}

bool PgDatabaseQuery::finish_(){
   TXDEBLOG(::titax_log(LOG_DEBUG, "PgDatabaseQuery::finalize()\n"));
   raw_query.clear();
   mBindParamsValues.clear();
   mBindParamsIsNULL.clear();
   mBindParams.clear();
   return (!raw_query.size() && !mBindParamsValues.size() && !mBindParamsIsNULL.size() && !mBindParams.size());
}

void PgDatabaseQuery::execute(){
   TXDEBLOG(::titax_log(LOG_DEBUG, "PgDatabaseQuery::execute()\n"));
   (void)this->execute_query_(false);
}

int PgDatabaseQuery::getValueAsInt(){
   TXDEBLOG(::titax_log(LOG_DEBUG, "PgDatabaseQuery::getValueAsInt()\n"));
   PGresult* const res=this->execute_query_();
   if (checkData(res)){
      const int value=::txpq_cv_int(res, 0, 0);
      if (res) ::txpq_reset(res);
      return value;
   }
   if (res) ::txpq_reset(res);
   //it is safe to remove as long as checkData can throw an exception
   //throw execution_error("getValueAsInt");
   return false;
}

std::vector<int> PgDatabaseQuery::getValueAsIntVector() {
   TXDEBLOG(::titax_log(LOG_DEBUG, "PgDatabaseQuery::getValueAsIntVector()\n"));
   
   PGresult* const res = this->execute_query_();
   if (res == nullptr) {
      return {};
   }

   ExecStatusType status = PQresultStatus(res);
   if (status != PGRES_TUPLES_OK && status != PGRES_SINGLE_TUPLE) {
       return {};
   }

   size_t num_rows = static_cast<size_t>(PQntuples(res));
   std::vector<int> intValues;
   intValues.reserve(num_rows);
           
   for (size_t i = 0; i < num_rows; i++) {         
      intValues.push_back(::txpq_cv_int(res, i, 0));
   }    
   
   PQclear(res);
   return intValues;
}

bool PgDatabaseQuery::appendValueToBuffer(std::string & pBuffer){
   TXDEBLOG(::titax_log(LOG_DEBUG, "PgDatabaseQuery::appendValueToBuffer()\n"));
   PGresult* const res=this->execute_query_();
   if (checkData(res)){
      if (const char * const p_=::txpq_cv_str(res, 0, 0)){
         pBuffer+=p_;
         if (res) ::txpq_reset(res);
         return true;
      }
   }
   if (res) ::txpq_reset(res);
   //it is safe to remove as long as checkData can throw an exception
   //else throw execution_error("appendValueToBuffer");
   return false;
}

bool PgDatabaseQuery::getValueAsStr(char * const pOutBuf, size_t * const pOutBuffSZ){
   if (pOutBuf && pOutBuffSZ && (*pOutBuffSZ)){
      PGresult* const res=this->execute_query_();
      if (checkData(res)){
         if (const char * const p_=::txpq_cv_str(res, 0, 0)){
            const size_t l_=::strlen(p_);
            ::strlcpy(pOutBuf,p_,*pOutBuffSZ);
            (void)(*pOutBuffSZ<l_ || (*pOutBuffSZ=l_));
            ::txpq_reset(res);
            return true;
         }
      }
      if (res) ::txpq_reset(res);
   }
   throw tools::errors::execution_error("getValueAsStr");
   //it is safe to remove this as long as code is compiled with support for the throwable exceptions
   //return false;
}

std::vector<std::vector<std::string>> PgDatabaseQuery::getRows() {
   auto result = this->execute_query_();
   if (result == nullptr) {
      return {};
   }

   switch (PQresultStatus(result)) {
   case PGRES_TUPLES_OK:
   case PGRES_SINGLE_TUPLE:
      break;
   default:
      return {};
   }

   std::vector<std::vector<std::string>> rows;

   int num_rows = PQntuples(result);
   int num_cols = PQnfields(result);
   for (int i = 0; i < num_rows; ++i) {
      std::vector<std::string> row={};
      for (int j = 0; j < num_cols; ++j) {
         row.emplace_back(PQgetvalue(result, i, j));
      }
      rows.emplace_back(std::move(row));
   }

   PQclear(result);

   return rows;
}

////////////////////////////////////////////////////////////////////////////////

PgDatabase::~PgDatabase(){
   this->finish_();
}

void PgDatabase::finish_(){
   mDatabase.reset();
}

const char * PgDatabase::errorMsg() const{
   if (mDatabase) return PQerrorMessage(mDatabase.get());
   return NULL;
}

void PgDatabase::execute(std::string query){
   TXDEBLOG(::titax_log(LOG_DEBUG, "PgDatabase::execute %s\n", query.c_str()));
   Database::DBQueryUniq q{this->query(query)};
   if (query.size()) q->execute();
}

bool PgDatabase::open(const std::string & constr){
   return open_(constr);
}

bool PgDatabase::open_(const std::string & constr){
   TXDEBLOG(::titax_log(LOG_DEBUG, "PgDatabase::open\n"));
   if (constr.size()){
      PGconn * const dbcon=::pq_conn(constr.c_str());
      if (::pq_is_alive(dbcon)){
         #ifndef TTN_ATESTS
            (void)::PQsetClientEncoding(dbcon, DEFAULT_CLIENT_ENCODING);
         #endif
         mDatabase.reset(dbcon);
         return true;
      }
   }
   throw tools::errors::unable_open_db_error();
   //it is safe to remove this as long as code is compiled with support for the throwable exceptions
   //return false;
}

bool PgDatabase::isOpen(){
   if (mDatabase){
      return (static_cast<bool>(::pq_is_alive(mDatabase.get())));
   }
   throw tools::errors::db_handler_error("isOpen");
}

bool PgDatabase::reOpen(){
   if (mDatabase){
      if (::pq_conn_reset(mDatabase.get())) return (true);
      TXDEBLOG(::titax_log(LOG_DEBUG, "PgDatabase::reOpen() failed:[%s]\n",this->errorMsg()));
      return (false);
   }
   throw tools::errors::db_handler_error("reOpen");
}

void PgDatabase::close(){
   this->finish_();
}

/* Create a query */
PgDatabase::DBQueryUniq PgDatabase::query(std::string q){
   if (this->isOpen()){
      auto * rq_ = new PgDatabaseQuery(*this);
      if (rq_){
         if (!q.size() || rq_->prepare(q)) 
            return PgDatabase::DBQueryUniq{rq_};
      }
   }
   throw tools::errors::new_query_error();
} 

void PgDatabase::performCopy(const char *sql, const char *data, size_t data_size) {
   std::string error;
   if (!startCopyMode(sql, &error)) {
      throw errors::copy_mode_error("failed to start : " + error ); 
   }

   std::string all_errors;

   if (!copyData(data, data_size, &error)) {
      all_errors += "failed to copy data : ";
      all_errors += error;
   }

   if (!endCopyMode(&error)) {
      if (!all_errors.empty()) {
         all_errors += "; ";
      }
      all_errors += "failed to end : ";
      all_errors += error;
   }

   if (!all_errors.empty()) {
      throw errors::copy_mode_error(all_errors); 
   }
}

bool PgDatabase::startCopyMode(const char *query, std::string *error_msg) {
   auto result = PQexec(mDatabase.get(), query);
   bool is_successful = PQresultStatus(result) == PGRES_COPY_IN;
   if (!is_successful && error_msg != nullptr) {
      *error_msg = PQresultErrorMessage(result);
   }
   PQclear(result);
   return is_successful;
}

bool PgDatabase::copyData(const char *data, size_t size, std::string *error_msg) {
   if (size > INT_MAX) {
      if (error_msg != nullptr) {
         *error_msg = "the size of the data is too large for PQputCopyData to handle";
      }
      return false;
   }
   if (INVALID_==PQputCopyData(mDatabase.get(), data, static_cast<int>(size)) ) {
      if (error_msg != nullptr) {
         *error_msg = PQerrorMessage(mDatabase.get());
      }
      return false;
   }
   return true;
}

bool PgDatabase::endCopyMode(std::string *error_msg) {
   if (INVALID_==PQputCopyEnd(mDatabase.get(), nullptr)) {
      if (error_msg != nullptr) {
         *error_msg = PQerrorMessage(mDatabase.get());
      }
      return false;
   }
   auto result = PQgetResult(mDatabase.get());
   bool is_successful = PQresultStatus(result) == PGRES_COMMAND_OK;
   if (!is_successful && error_msg != nullptr) {
      *error_msg = PQresultErrorMessage(result);
   }
   PQclear(result);
   return is_successful;
}

/* Test for existence of an index */
bool PgDatabase::indexExists(const char *indexName){
   if (indexName){
      PgDatabaseQuery q(*this);
      q.prepare(std::string{"SELECT COUNT(*) FROM pg_indexes WHERE indexname=?;"});
      q.bind(1, indexName);
      int result = q.getValueAsInt();
      return (result != 0);
   }
   return false;
}

/* Test for existence of a table */
bool PgDatabase::tableExists(const std::string & tname){
   if (tname.size()){
      PgDatabaseQuery q(*this);
      q.prepare(std::string{"SELECT COUNT(tablename) FROM pg_tables WHERE tablename=?;"});
      q.bind(1, tname.c_str());
      int result = q.getValueAsInt();
      return (result != 0);
   }
   return false;
}

/* Test for existence of a view */
bool PgDatabase::viewExists(const char *viewName){
   if (viewName){
      PgDatabaseQuery q(*this);
      q.prepare(std::string{"SELECT COUNT(*) FROM pg_views WHERE viewname=?;"});
      q.bind(1, viewName);
      int result = q.getValueAsInt();
      return (result != 0);
   }
   return false;
}

/* Test for existence of a function */
bool PgDatabase::functionExists(const char *functionName){
   if (functionName){
      PgDatabaseQuery q(*this);
      q.prepare(std::string{"SELECT COUNT(*) FROM pg_proc WHERE proname=?;"});
      q.bind(1, functionName);
      int result = q.getValueAsInt();
      return (result != 0);
   }
   return false;
}

/* Test for existence of a trigger */
bool PgDatabase::triggerExists(const char *triggerName){
   if (triggerName){
      PgDatabaseQuery q(*this);
      q.prepare(std::string{"SELECT COUNT(*) FROM pg_trigger WHERE tgname=?;"});
      q.bind(1, triggerName);
      int result = q.getValueAsInt();
      return (result != 0);
   }
   return false;
}

/* Test for existence of a database */
bool PgDatabase::databaseExists(const char *databaseName){
   if (databaseName){
      PgDatabaseQuery q(*this);
      q.prepare(std::string{"SELECT COUNT(*) FROM pg_database WHERE datname=?;"});
      q.bind(1, databaseName);
      int result = q.getValueAsInt();
      return (result != 0);
   }
   return false;
}

char * PgDatabase::escapeLiteral( const char *data, size_t dsz) {

   return txpq_escape_literal(mDatabase.get(), data, dsz);
}
