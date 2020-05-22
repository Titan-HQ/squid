/*
 * $Id$
 */
#ifndef DB_PG_HXX
#define DB_PG_HXX
#include <vector>       // stl vector header
#include <string>
#include <utility>

#include <libpq-fe.h>
#include "ttn_tools.hxx"

#define DEFAULT_CLIENT_ENCODING  "LATIN1"

namespace titan_v3{

   namespace tools{

      struct PGresult_reseter { 
        void operator()(PGresult*) const noexcept;
      };

      using pgresult_uniq_t=std::unique_ptr<    PGresult,
                                                PGresult_reseter >;

      class PgDatabase;

      class PgDatabaseQuery : public DatabaseQuery<PgDatabase,PGresult*,PGresult**>{

         public:
            using DatabaseQuery::DatabaseQuery;

            ~PgDatabaseQuery()override{
               this->finish_();
            }

            /* Prepare a query */
            bool prepare(std::string,const bool auto_reset=false) override;
            bool reprepare(const bool auto_reset=false) override{ 
               if (auto_reset){
                  std::string tmp_old_q{std::move(this->raw_query)};
                  (void)this->reset();
                  this->raw_query=std::move(tmp_old_q);
               }
               return ((mQuery = convertPlaceholders_()).size()>0);
            }
            bool reset() override;
            /* Execute the prepared statement, no return value expected */
            void execute() override;
            bool execute(PGresult **,const bool throw_exception_if_no_data=true) override;
            bool execute(t_query_lamda lmbd,const bool throw_exception_if_no_data=true) override;
            void closeRS(PGresult*) override;
            /* Execute the prepared statement and return a single integer from the
             first column, first row */
            int getValueAsInt() override;
            std::vector<int> getValueAsIntVector() override;
            bool appendValueToBuffer(std::string & pBuffer) override;
            bool getValueAsStr(char * const pOutBuf, size_t * const pOutBuffSZ) override;

            /* Return result rows.
             *
             * Example:
             *
             * query = database.query("select 'aaa', 'bbb', 'ccc' "
             *                        "union "
             *                        "select 'one', 'two', 'three';");
             *
             * for (auto& row : query.getRows()) {
             *    for (auto& cell : row) {
             *       std::cout << cell << ' ';
             *    }
             *    std::cout << std::endl;
             * }
             *
             * // Outputs:
             * //  aaa bbb ccc
             * //  one two three
             */
            std::vector<std::vector<std::string> > getRows() override;

            /* Finalize a statement */
            void finalize() override {
               this->finish_();
            }

      #ifdef TTN_ATESTS

            const std::vector<char*> & get_mBindParamsValues_4tests()const{
               return mBindParamsValues;
            }

            const std::string & get_mQuery_4tests()const{
               return mQuery;
            }

            const globals::strings_t & get_mBindParams_4tests()const{
               return mBindParams;
            }

            const std::vector<bool> & get_mBindParamsIsNULL_4tests()const{
               return mBindParamsIsNULL;
            }


      #endif
         protected:

            PGresult* execute_query_(const bool data_expected=true);
            void prepareBindParams_();
            std::string convertPlaceholders_();
            /**
             * Check is new param is beyond current range
             * @param pos : new param
             */
            inline
            void checkBindParamsSize_(const size_t pos){
               if (mBindParams.size() < pos+1){
                  mBindParams.resize(pos+1);
                  mBindParamsIsNULL.resize(pos+1);
               }
            }
            bool setBindParam(const size_t pos, std::ostringstream&) override;
            bool setBindParam(const size_t pos) override;
            bool setBindParam(const size_t pos, titan_v3::tools::functors::templates::tos && ) override;
            std::mutex                 mBindParams_lock;
            std::vector<char*>         mBindParamsValues{};
            std::string                mQuery{};
            globals::strings_t         mBindParams{};
            std::vector<bool>          mBindParamsIsNULL{};
            std::string                raw_query{};
            bool finish_();
      public:
            const std::string & last_query{raw_query};

      };

      struct PGconn_deleter { 
         void operator()(PGconn* ptr) const;
      };

      class PgDatabase : public Database<PGconn,PgDatabaseQuery,PGconn_deleter>{
         public:
            using Database::Database;

            explicit PgDatabase(const std::string & cinfo={}){
               if (cinfo.size()){
                  (void)this->open_(cinfo);
               }
            }

            ~PgDatabase() override;

            /**
             * Open a database, can throw an exception 
             * @param : connect string
             * @return 
             */
            bool open(const std::string &) override;

            /**
             * Close the database
             */
            void close() override;

            /* Test for existence of an index */
            bool indexExists(const char *) override;
            /* Test for existence of a table */
            bool tableExists(const std::string &) override;
            /* Test for existence of a view */
            bool viewExists(const char *) override;
            /* Test for existence of a function */
            bool functionExists(const char *) override;
            /* Test for existence of a trigger */
            bool triggerExists(const char *) override;
            /* Test for existence of a database */
            bool databaseExists(const char *) override;
            /* Execute a query */
            void execute(std::string) override;
            /* Get last error message */
            const char *errorMsg() const override;
            /* Create a query */
            DBQueryUniq query(std::string) override;
            /*
             * https://www.postgresql.org/docs/9.4/static/sql-copy.html
             *
             * Start the COPY mode by executing the given SQL (which must
             * be a single COPY command which instructs PostgreSQL to read from
             * STDIN) and copy the given data of given size into the database.
             *
             * In case of any error - an std::runtime_error is thrown, but
             * before that, an attempt is made to end COPY mode if it was
             * started.
             */
            void performCopy(const char *sql, const char *data, size_t data_size);
            bool isOpen() override;
            bool reOpen() override;
            friend class PgDatabaseQuery;
            void finish_();
            /**
             * @fn escapeLiteral
             * @param data[in]
             * @param dsz[in]
             * @return new buffer or null
             */
            char * escapeLiteral(const char *, const size_t );
           
      protected:
            PgDatabase::DBQueryUniq check_table;
            bool open_(const std::string &);
      private:
            /*
             * Start the COPY mode by executing the given SQL query which must
             * contain the COPY command.
             *
             * IMPORTANT: a database connection which is in COPY mode CANNOT be
             * used for anything else (i.e. ordinary SQL queries) until the COPY
             * mode is ended! To end the COPY mode, call the endCopyMode() method.
             *
             * See also copyData(), endCopyMode(), performCopy().
             */
            bool startCopyMode(const char *query, std::string *error_msg = nullptr);

            /*
             * Copies the given data of the given size to the database.
             * The connection must be in COPY mode which is started by the
             * startCopyMode method.
             *
             * See also startCopyMode(), endCopyMode(), performCopy().
             */
            bool copyData(const char *data, size_t size, std::string *error_msg = nullptr);

            /*
             * Ends the COPY mode on this database connection, after which it
             * can be used normally again, i.e. ordinary SQL queries can be
             * executed.
             *
             * See also startCopyMode(), copyData(), performCopy().
             */
            bool endCopyMode(std::string *error_msg = nullptr);

      };

   }; /* tools namespace */

}; /* titan_v3 namespace */
#endif
