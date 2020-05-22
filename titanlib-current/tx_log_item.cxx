/**
 * $Id$
 * 
 */
#include "tx_log_item.hxx"

void titan_v3::tx_log_parser::parse_extra_fields__(   const char * msg_,
                                                      tx_log_item & out_item  ) noexcept
{

#if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )
// remove this "swiss-cheese" macro when we finally start building only on the FB11+

   while ( ( msg_ = strchr( msg_, '\n' ) ) != nullptr ) {

      // Find length of line
      const char * nextnl{};
      size_t length{};
      ptrdiff_t dsz{};

      if (  ( nextnl = ::strchr( ++msg_, '\n' ) )  &&

            ptr_diff( nextnl, msg_, &dsz )         && 

            dsz                                       ) {

         length = static_cast<size_t>(dsz-1);
      }

      switch ( *msg_ ) {

         default:break;
         case 'C': out_item.Categories.emplace_back (msg_+1, length );        break;
         case 'N':
         case 'E': out_item.Emails.emplace_back( msg_+2, length-1 );          break;
         case 'G': out_item.Groups.emplace_back( msg_+1, length );            break;
         // internal ip
         case 'I': out_item.mInternalIp = std::string{ msg_+1, length };      break;
         case 'K': out_item.CloudKey = std::string{ msg_+1, length };         break;
         case 'L': out_item.Location = std::string{ msg_+1, length };         break;
         // policy name      
         case 'P': out_item.PolicyName = std::string{ msg_+1, length };       break;
         case 'R': out_item.Reason = std::string{ msg_+1, length };           break;
         // customer id from titax database
         case 'S': out_item.CustomerId = std::string{ msg_+1, length};        break;
         // internal user id
         case 'U': out_item.InternalUser = std::string{ msg_+1, length };     break;
         // extention field for ip v4 and/or ip v6
         case 'V': out_item.mIp = std::string{ msg_+1, length };              break;

      }

   } /* loop */

#endif

}
