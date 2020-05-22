/**
 * $Id$
 */

#include "ttn_locations.hxx"
#include "edgepq.h"
#include "sqls.h"
#include "ttn_tools.hxx"
#include "log.h"
#ifdef TTN_ATESTS
#include "wada_api.h"
#endif


namespace titan_v3 {

    namespace locations {

        bool locations_box_type::save4wada( const char * const filename,
                                            const bool append            ) noexcept {

            if (    filename &&
                    filename[0] )   {

                std::lock_guard<std::mutex> slock{this->lock};

                if ( box.box_.size() ) {

                    FILE *const fout{ fopen( filename, 
                                             (append?"a+":"w+")  )}; 

                    if ( fout ) {

                        char c_{ !append?'*':'+' };

                        for (const auto & l:box){

                            #ifdef TTN_ATESTS
                                s4test.save.ctx++;
                            #endif

                            if ( location_t::types::wada == l.type ){
                                const std::string & hex_ipv4 = factory::to_hex( l.cidr.addr );
                                const std::string & uuid_str = l.uuid;

                                #ifdef TTN_ATESTS
                                    const auto stat=fprintf (fout, "%c%8s%s\n", c_, hex_ipv4.c_str(), uuid_str.c_str());
                                    if ( stat>0 ){
                                        s4test.save.bytes+=static_cast<size_t>(stat);
                                        s4test.save.lines++;
                                    }

                                #else
                                    (void)fprintf (fout, "%c%8s%s\n", c_, hex_ipv4.c_str(), uuid_str.c_str());
                                #endif

                                c_='+'; 

                            }

                        }

                        fclose (fout);
                        return true;

                    }

                }

            }

            return false;

        }

        bool locations_box_type::reload(PGconn* const __restrict  db) noexcept {

            if (db){

                box.reset<location_t::types::db>();

                pgresult_uniq_t rset{pq_get_rset(db, TITAXLIB_QS_V_LOCATIONS)};

                if (rset){

                    auto rset_ = rset.get();

                    if ( const uint_fast64_t max = txpq_row_count(rset_) ){

                        std::lock_guard<std::mutex> mlock{this->lock};

                        for (uint_fast64_t i=0; i<max;++i){

                            /* 
                             * If the user id is zero we should ignore this record.
                             * If the policy id is zero we should use the UNASSIGNED const.
                             */

                            const user_id_t user_id{ txpq_cv_ulong(rset_, i, 0) };

                            const policy_id_t policy_id{ txpq_cv_int(rset_, i, 7) };

                            const int ipt{ txpq_cv_int(rset_, i, 1) };

                            std::string last_loc_value{"<INVALID>"};

                            std::string err_msg{};

                            if ( ipt < 3 ){ // Condition should be guaranteed by the sql query

                                using namespace cidr;

                                const char * loc_name{};

                                if ( txpq_cv_int(rset_, i, 3) ){

                                    loc_name = txpq_cv_str(rset_, i, 4);

                                }

                                switch (ipt){

                                    case 1:{//cidr/host ip

                                        const char * const ip_str = txpq_cv_str(rset_, i, 2);

                                        if ( ip_str ) {

                                               auto host = factory::make_cidr(ip_str);

                                               if ( host.second ) {

                                                  const auto cidr = std::move( host.first );

                                                  try {

                                                      const bool ts_flag = txpq_cv_bool(rset_, i, 6);

                                                      if ( this->load( {   cidr,
                                                                           user_id,
                                                                           location_t::types::db,
                                                                           loc_name,
                                                                           policy_id,
                                                                           ts_flag                  } ) ) {
                                                         continue;
                                                      }

                                                  } catch ( const std::exception & e ) {
                                                      err_msg = e.what();
                                                  }

                                                  last_loc_value = factory::to_string(cidr);
                                               }
                                        }

                                    } break;

                                    case 2:{ //vlocations

                                        const char * const loc_tag = txpq_cv_str(rset_, i, 5);

                                        if ( loc_tag && loc_tag[0] ) {

                                            try {

                                               if ( this->load( {  loc_tag,
                                                                   user_id,
                                                                   location_t::types::db,
                                                                   loc_name,
                                                                   policy_id                } ) ) {

                                                   continue;
                                               }

                                            } catch ( const std::exception & e ) {
                                                err_msg = e.what();
                                            }

                                            last_loc_value = loc_tag;
                                        }

                                    }break;

                                    default: break;

                                } /* switch */

                            } /* if */

                            titax_log(  LOG_WARNING,
                                        "fail to load the location of type %d and of value %s %s\n",
                                        ipt,
                                        ( last_loc_value.c_str() ?: "<INVALID>"),
                                        ( err_msg.c_str() ?: "" )                                     );


                        } /* for loop */

                    }

                    return true;

                }

            }

            return false;

        }

    } // namespace locations

} // namespace titan_v3

/* vim: set ts=4 sw=4 et : */

