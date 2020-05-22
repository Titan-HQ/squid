/**
 * $Id$
 */

#ifndef TTN_SQL_TOOLS_HXX
#define TTN_SQL_TOOLS_HXX
#include <string>
#include "global.h"
#include "ttn_status_pair.hxx"
#include "ttn_functors_templates.hxx"

namespace titan_v3{

   namespace tools{

      namespace sql{
     
         using sql_pair_t = tools::status_pair_t<std::string>;

         namespace { /* private */

            using namespace titan_v3::tools::functors;
            using citer_ols = templates::citer_fn< templates::citer_cfg::cfg_ols >;
         }

         /**
          * @template  make_update_users_bw
          * @param ids[in]: TI (e.g. vector etc)
          * @param bandwidths[in]: TB (e.g. vector etc)
          * @return sql_pair_t (first:std::string, second:bool)
          */
         template <typename TI, typename TB>
         TX_CPP_INLINE_LIB   
         sql_pair_t make_update_users_bw(const TI & ids, const TB & bandwidths ){

            if ( const auto ids_sz=ids.size()){

               if (ids_sz==bandwidths.size()){

                  constexpr const char UPD_USERS_BW_SQL_BEGIN[]  = "select update_users_bw(\'\' , ARRAY[";
                  constexpr const char UPD_USERS_BW_SQL_MID[]    = "] , ARRAY[";
                  constexpr const char UPD_USERS_BW_SQL_END[]    = "])";
                  constexpr const auto UPD_USERS_BW_SQL_MIN_SZ   = ( (sizeof(UPD_USERS_BW_SQL_BEGIN)-1) +
                                                                     (sizeof(UPD_USERS_BW_SQL_MID)-1) +
                                                                     (sizeof(UPD_USERS_BW_SQL_END)-1) );

                  using namespace titan_v3::tools::functors::templates;

                  std::string sql = tos{  UPD_USERS_BW_SQL_BEGIN }      <<
                                          citer_ols{ ids,"," }          <<
                                          UPD_USERS_BW_SQL_MID          <<
                                          citer_ols{ bandwidths,"," }   <<
                                          UPD_USERS_BW_SQL_END;

                  if ( UPD_USERS_BW_SQL_MIN_SZ < sql.size() )
                     return sql_pair_t::success(sql);

               }

            }

            return sql_pair_t::failure();

         }

      }; /* sql namespace */

   }; /* tools namespace */

}; /* titan_v3 namespace */

#endif /* TTN_SQL_TOOLS_HXX */

