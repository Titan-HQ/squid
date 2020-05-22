/*
 * $Id$
 * 
 */

#ifndef TTN_GLOBAL_HXX
#define TTN_GLOBAL_HXX

#include "global.h"
#include "TitaxUser.h"
#include "ttn_status_pair.hxx"
#include <string>
#include <vector>
#include <map>

namespace titan_v3 {

   namespace globals {
      struct strptr:public t_strptr{
         strptr(const char * p, const size_t s):t_strptr{p,s}{}
         strptr(const strptr & p):t_strptr{p.ptr_,p.sz_}{}
         strptr(strptr && p):t_strptr{nullptr,0} {
            std::swap(ptr_,p.ptr_);
            std::swap(sz_,p.sz_);
         }
      }; /* class */ 

      using raw_parts_t = std::vector<strptr>;

      using strings_t = std::vector<std::string>;

      using users_policies_t = std::map<user_id_t, policies_t>;

      using update_status_t = tools::status_pair_t<users_policies_t>;

   }  /* namespace */
} /* namespace */

#endif /* TTN_GLOBAL_HXX */

