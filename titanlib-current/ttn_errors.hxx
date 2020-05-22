/*
 * $Id$
 *
 */
#ifndef TTN_ERRORS_HXX
#define TTN_ERRORS_HXX
#include <exception>
#include <stdexcept>

namespace titan_v3 {

    namespace tools{

        namespace errors{

            struct constraint_violation_error : std::runtime_error{

                constraint_violation_error() :  std::runtime_error("Constraint violation")
                                                {}
            };

            struct db_handler_error : std::runtime_error{

                db_handler_error() :    std::runtime_error("DB Handler is invalid")
                                        {}

                explicit db_handler_error(const std::string & msg) :    std::runtime_error( std::string{"DB Handler is invalid ("+msg+")"})
                                                                        {}

            };

            struct unable_open_db_error : std::runtime_error{

                unable_open_db_error() :    std::runtime_error("Unable to open database")
                                            {}
            };

            struct client_encoding_error : std::runtime_error{

                client_encoding_error() :   std::runtime_error("Cannot set client encoding")
                                            {}
            };

            struct execution_error : std::runtime_error{

                execution_error() : std::runtime_error("Execution Failure")
                                    {}

                explicit execution_error(const std::string & where) :   std::runtime_error(std::string{"Execution Failure ("+where+")"})
                                                                        {}

            };

            struct no_data_error : execution_error{

                no_data_error() :   execution_error("no data")
                                    {}
            };

            struct new_query_error : execution_error{

                new_query_error() : execution_error("couldn't create a new query")
                                    {}

                explicit new_query_error(const std::string & trace) :   execution_error(std::string{"couldn't create a new query ["+trace+"]"})
                                                                        {}

            };

            struct execute_query_error : execution_error{

                execute_query_error() : execution_error("unable to execute a query")
                                        {}
            };

            struct copy_mode_error : std::runtime_error{

                copy_mode_error(const std::string & msg) :  std::runtime_error( "COPY MODE ERROR : " + msg )
                                                            {}
            };

            struct low_position_error : std::out_of_range{

                low_position_error() :  std::out_of_range("position is too low")
                                        {}
            };

            struct logger_cfg_error : execution_error{

                logger_cfg_error() :    execution_error("logger config is empty/null")
                                        {}
            };

            struct urlcache_error : execution_error{

                urlcache_error() :  execution_error("creating urlcache has failed")
                                    {}
            };

            struct hexdump_error : std::runtime_error{

                hexdump_error() :   std::runtime_error("invalid arguments")
                                    {}
            };

            struct sbuff_storage_error : std::runtime_error{

            sbuff_storage_error() : std::runtime_error("storage error")
                                    {}
            };

            struct nullptr_error : std::invalid_argument{

                nullptr_error() :   std::invalid_argument("null pointer")
                                    {}

                explicit nullptr_error(const std::string & trace) : std::invalid_argument(std::string{"null pointer ["+trace+"]"})
                                                                    {}

            };

            struct assign_error : std::invalid_argument{

                assign_error() :    std::invalid_argument("assign error")
                                    {}

                explicit assign_error(const std::string & trace) :  std::invalid_argument(std::string{"assign pointer ["+trace+"]"})
                                                                    {}

            };

            struct swap_error : std::invalid_argument{

                swap_error() :  std::invalid_argument("swap error")
                                {}

                explicit swap_error(const std::string & trace) :    std::invalid_argument(std::string{"swap pointer ["+trace+"]"})
                                                                    {}

            };

            struct EHTCollision : execution_error{

                EHTCollision() :    execution_error("[EHTCollision]::Unhandled Collision!")
                                    {}
            };

            struct EHTNotFound : execution_error{

                EHTNotFound() : execution_error("[EHTNotFound]::Entry not found!")
                                {}
            };

            struct EHTHashingError : execution_error{

                EHTHashingError() : execution_error("[EHTHashingError]::Problem with the hash!")
                                    {}
            };

            struct EPolicyError : execution_error{

                EPolicyError() :    execution_error("[EPolicyError]::Problem with the policy id!")
                                    {}
            };

            struct EHTDuplicates : execution_error{

                EHTDuplicates() :   execution_error("[EHTDuplicates]::Duplicates!")
                                    {}
            };

            struct context_is_null : std::runtime_error{

                context_is_null() : std::runtime_error("The Scheduled Context cannot be null at this stage!!!")
                                    {}
            };

            struct domain_parser_too_many_lbls_error : execution_error{

                domain_parser_too_many_lbls_error() :   execution_error("domain parser error: too many labels")
                                                        {}
            };

            struct domain_parser_invalid_length : execution_error{

                domain_parser_invalid_length( const size_t l ) :    execution_error("domain parser error: invalid length "+std::to_string(l) )
                                                                    {}
            };

            struct domain_parser_invalid_lbl_lenght_error : std::exception{

                domain_parser_invalid_lbl_lenght_error(	const ssize_t l,
                                                        const char * const d ) : msg { "domain parser error: label is too short or too long "}
                {
                    this->msg+=std::to_string( l );
                    this->msg+='[';
                    this->msg+=(d?:"<NULL>");
                    this->msg+=']';
                }

                const char* what() const noexcept final {
                    return this->msg.c_str();
                }

                protected:
                    std::string msg{};

            };

            struct safe_search_error : execution_error{

                safe_search_error(const std::string & s) :  execution_error("unable to apply " + s + " safe search restrictions")
                                                            {}
            };


            struct wada_init_error : execution_error{

                wada_init_error() : execution_error( "Can't initialise a second wada instance!" )
                                    {}
            };


            struct urldb_connection_error : execution_error{

                urldb_connection_error() :  execution_error( "urldb connection error" )
                                            {}
            };

            struct location_error : execution_error
            {

                location_error(const std::string & s) :  execution_error{s}
                {
                     /* empty */
                }
            };

            struct lock_error : execution_error
            {

                lock_error(const std::string & s) :  execution_error{s}
                {
                     /* empty */
                }
            };

      } /* errors namespace */

   } /* tools namespace */

} /* titan_v3 namespace */


#endif /* TTN_ERRORS_HXX */

/* vim: set ts=4 sw=4 et : */
