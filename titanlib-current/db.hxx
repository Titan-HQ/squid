/*
 * $Id$
 */
#ifndef DB_HXX
#define DB_HXX

#include <string>
#include <sstream>
#include <iostream>
#include <cassert>
#include "ttn_traits.hxx"
#include "ttn_errors.hxx"
#include "ttn_functors_templates.hxx"

namespace titan_v3{

   namespace tools{

      using namespace functors::templates;

      template <class TDBTYPE,typename TRSTYPE,typename TRSTYPE_EXEC>
      class DatabaseQuery{
      protected:

         TDBTYPE & mDatabase;
         virtual bool setBindParam(const size_t pos, std::ostringstream & )=0;
         virtual bool setBindParam(const size_t pos, tos && )=0;
         virtual bool setBindParam(const size_t pos)=0;
         DatabaseQuery(const DatabaseQuery&);
         DatabaseQuery& operator=(const DatabaseQuery&);
      public:
         typedef std::function<void(TRSTYPE r_)> t_query_lamda;

         explicit DatabaseQuery(TDBTYPE & db):mDatabase(db){}
         virtual ~DatabaseQuery()=default;

         /* Prepare a query */
         virtual bool prepare(std::string,const bool auto_reset=false) = 0;

         inline bool prepare(const char *const query,const bool auto_reset=false){
            return (query?prepare(std::string{query},auto_reset):false);
         }

         virtual bool reprepare(const bool auto_reset=false)=0;

         /**
          * bind a parameter 
          * @param value   : pair of [pos and value]
          * @return        : t/f
          */
         template <class TINPUT_PAIR>
         typename std::enable_if<titan_v3::tools::traits::is_pair<TINPUT_PAIR>::value,bool>::type
         bind(TINPUT_PAIR value){
            return this->setBindParam(value.first,tos{value.second});  
         }

         /**
          * bind a parameter 
          * @param pos     : index starts from 1
          * @param value   : value 
          * @return        : t/f
          */
         template <typename TINPUT>
         typename std::enable_if<!titan_v3::tools::traits::is_pair<TINPUT>::value,bool>::type
         bind(const size_t pos, const TINPUT & value){
            return this->setBindParam(pos,tos{value}); 
         }

         /**
          * bind a null parameter
          * @param pos  : index starts from 1
          * @return     : t/f
          */   
         bool bind(const size_t pos){
            return this->setBindParam(pos);
         }

         /* reset prepared query */
         virtual bool reset()=0;
         /* Execute the prepared statement, no return value expected */
         virtual void execute() = 0;
         virtual bool execute(TRSTYPE_EXEC,const bool throw_exception_if_no_data=true)=0;
         //virtual bool execute(t_query_lamda lmbd=[](TRSTYPE r_){})=0;
         virtual bool execute(t_query_lamda lmbd,const bool throw_exception_if_no_data=true)=0;
         virtual void closeRS(TRSTYPE)=0;
         /* Execute the prepared statement and return a single integer from the
          first column, first row */
         virtual int getValueAsInt() = 0;

         /* Execute the prepared statement and return an integer vector from the first column */
         virtual std::vector<int> getValueAsIntVector() = 0;
         /* Execute the prepared statement and return a str_char from the
          first column, first row */
         virtual bool getValueAsStr(char * const pOutBuf, size_t * const pOutBuffSZ) = 0;
         virtual bool appendValueToBuffer(std::string &pBuffer) = 0;
         virtual std::vector<std::vector<std::string> > getRows() = 0;
         
         /* Finalize a prepared query */

         virtual void finalize() = 0;

      };

      template <typename TDBTYPE,class TQUERY, class TDBTDEL=std::default_delete<TDBTYPE>>
      class Database{
         public:
            typedef std::unique_ptr<TDBTYPE,TDBTDEL> DBUniq;
            typedef std::unique_ptr<TQUERY> DBQueryUniq;

            Database(){}

            /* Destructor */
            virtual ~Database()=default;

            /**
             * open connection to the DB 
             * @param : constr 
             */
            virtual bool open(const std::string&){
               assert(0 && "not implemented yet");
               return false;
            }

            inline bool open(const char * const constr){
               return (constr?open(std::string{constr}):false);
            }

            /* Close the database */
            virtual void close() = 0;

            /* Test for existence of an index */
            virtual bool indexExists(const char *indexName) = 0;

            /* Test for existence of a table */
            
            virtual bool tableExists(const std::string & tableName) = 0;
            
            bool tableExists(const char *tableName){               
               if (tableName) return tableExists(std::string{tableName}) ;
               throw tools::errors::nullptr_error();
            }

            /* Test for existence of a view */
            virtual bool viewExists(const char *viewName) = 0;

            /* Test for existence of a function */
            virtual bool functionExists(const char *functionName) = 0;

            /* Test for existence of a trigger */
            virtual bool triggerExists(const char *triggerName) = 0;

            /* Test for existence of a database */
            virtual bool databaseExists(const char *databaseName) = 0;

            /* Execute a query */
            virtual void execute(std::string) = 0;

            inline void execute(const char *const query){
               if (query) execute(std::string{query});
               throw tools::errors::nullptr_error();
            }

            /* Get last error message */
            virtual const char *errorMsg() const = 0;

            /* Create a query */
            virtual DBQueryUniq query(std::string) = 0;

            virtual bool isOpen()=0;
            virtual bool reOpen()=0;

         protected:
            DBUniq mDatabase;
            /* Disallow copy/move constructor/assignment */
            Database(const Database&);
            Database& operator=(const Database&);
            Database(const Database&&);
            Database& operator=(const Database&&);
      };

   }; /* tools namespace */

}; /* titan_v3 namespace */

#endif
