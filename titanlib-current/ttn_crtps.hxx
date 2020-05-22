/**
 *  $Id$
 */

#ifndef TTN_CRTPS_HXX
#define TTN_CRTPS_HXX
#include <type_traits>
#include <typeinfo>
#include "ttn_traits.hxx"
#include "ttn_tools.hxx"

namespace titan_v3{

   namespace tools{

      #ifndef GET_TYPE
         #define GET_TYPE(OBJ)   typename decltype(OBJ)
      #endif

      /**
       * CRTP aka Static Polymorphism
       * All templates follows the crtp pattern (somewhat similar to the Strategy/Policy pattern)
       * @ref https://en.wikipedia.org/wiki/Curiously_recurring_template_pattern
       * @ref http://en.cppreference.com/w/cpp/language/parameter_pack
       * @ref http://en.cppreference.com/w/cpp/language/class_template
       * @ref http://en.cppreference.com/w/cpp/language/function_template
       */
      namespace crtps
      {
         /**
          * @template crtp_mixin_type
          * @abstract crtp mixin template
          */
         template <class CRTP, template <typename... > class... CRTPS>
         struct crtp_mixin_type : CRTPS<CRTP>... {
         };/* crtp_mixin_type template */

         /**
          * @template box_mixin_type
          * @abstract It's a box mixin that includes the ibox_type (a polymorphic interface of a box)
          */
         template<typename BOX, template <typename... > class... CRTPS>
         struct box_crtp_mixin_type : CRTPS<box_crtp_mixin_type<BOX,CRTPS...>>...{
            using box_type=BOX;

            template <typename... Args>
            box_crtp_mixin_type(Args&&... args) : box{std::forward<Args>(args)...}{}

            box_crtp_mixin_type() = default;

            protected:
               mutable box_type box; /* for clang 3.4 : no initialization list */
         };/* box_crtp_mixin_type template */

         /**
          * @template ibox_type
          * @abstract Provides a polymorphic interface.
          * This template is compatible with the crtp_mixin_type.
          *
          * 
          */
         template <class CRTP>
         struct ibox_type
         {
            using self_type = ibox_type;
            /**
             * @fn add 
             * @abstract universal perfect forwarding variadic function template
             * @param args [in] param pack 
             * @return deducted type based on TAG typename
             */
            template<class D = CRTP, typename TAG=typename D::add_tag,typename... Args>
            inline auto add(Args&&... args) 
               -> decltype (traits::selfie<TAG,D>(this)->operator()(args...)){
                  return traits::selfie<TAG,D>(this)->operator()(std::forward< Args >(args)...);
            }

            /**
             * @fn del
             * @abstract universal perfect forwarding variadic function template
             * @param args [in] param pack
             * @return deducted type based on TAG typename
             */
            template<class D=CRTP, typename TAG=typename D::del_tag, typename... Args>
            inline auto del(Args&&... args) 
               -> decltype (traits::selfie<TAG,D>(this)->operator()(args...)){
                  return traits::selfie<TAG,D>(this)->operator()(std::forward< Args >(args)...);
            }

            /**
             * @fn find
             * @abstract universal perfect forwarding variadic function template
             * @param args [in] param pack
             * @return deducted type based on TAG typename
             */
            template<class D=CRTP, typename TAG=typename D::find_tag, typename... Args>
            inline auto find(Args&&... args) noexcept
               -> decltype (traits::selfie<TAG,D>(this)->operator()(args...)){
                  return traits::selfie<TAG,D>(this)->operator()(std::forward< Args >(args)...);
            }

            /**
             * @fn map_interface::operatop[]
             * @abstract universal perfect forwarding variadic function template
             * @param args [in] param pack
             * @return deducted type based on TAG typename
             */
            template<class D=CRTP, typename TAG=typename D::subscript_tag, typename... Args>
            inline auto operator[](Args&&... args) 
               -> decltype (traits::selfie<TAG,D>(this)->operator()(args...)){
                  return traits::selfie<TAG,D>(this)->operator()(std::forward< Args >(args)...);
            }

            /**
             * @fn size 
             * @abstract universal perfect forwarding variadic function template
             * @param args [in] param pack
             * @return deducted type based on TAG typename
             */
            template<class D=CRTP, typename TAG=typename D::size_tag, typename... Args>
            inline auto size(Args&&... args) const noexcept
               -> decltype (traits::selfie<TAG,D>(this)->operator()(args...)){
                  return traits::selfie<TAG,D>(this)->operator()(std::forward< Args >(args)...);
            }

            /**
             * @fn count
             * @abstract universal perfect forwarding variadic function template
             * @param args [in] param pack
             * @return deducted type based on TAG typename
             */
            template<class D=CRTP, typename TAG=typename D::count_tag, typename... Args>
            inline auto count(Args&&... args) const noexcept
               -> decltype (traits::selfie<TAG,D>(this)->operator()(args...)){
                  return traits::selfie<TAG,D>(this)->operator()(std::forward< Args >(args)...);
            }

            /**
             * @fn clear
             * @abstract universal perfect forwarding variadic function template
             * @param args [in] param pack
             * @return deducted type based on TAG typename
             */
            template<class D=CRTP, typename TAG=typename D::clear_tag, typename... Args>
            inline auto clear(Args&&... args) noexcept
               -> decltype (traits::selfie<TAG,D>(this)->operator()(args...)){
                  return traits::selfie<TAG,D>(this)->operator()(std::forward< Args >(args)...);
            }

            /**
             * @fn reset
             * @abstract universal perfect forwarding variadic function template
             * @param args [in] param pack
             * @return deducted type based on TAG typename
             */
            template<class D=CRTP, typename TAG=typename D::reset_tag, typename... Args>
            inline auto reset(Args&&... args) 
               -> decltype (traits::selfie<TAG,D>(this)->operator()(args...)){
                  return traits::selfie<TAG,D>(this)->operator()(std::forward< Args >(args)...);
            }

            /**
             * @fn map_interface::operator<<
             * @abstract universal function template
             * @param out [in] std::ostream
             * @param obj [in] CRTP 
             * @return std::ostream&
             */
            friend std::ostream& operator<<(std::ostream & out,const CRTP & obj ) noexcept {
               return traits::selfie<typename CRTP::out_tag,self_type>(obj)(out,obj);
            }

         }; /* ibox_type template */


         /**
          * @template box_type
          * @abstract a specialized template alias for box_crtp_mixin_type 
          */
         template<typename BOX, template <typename... > class... OPS>
         struct box_type : box_crtp_mixin_type<BOX,ibox_type,OPS...>{
            using box_crtp_mixin_type<BOX,ibox_type,OPS...>::box_crtp_mixin_type;
         };

         /**
          * @template add_op_type
          * @abstract A universal add_tag functor. 
          * This template is compatible with the crtp_mixin_type.
          *
          */
         template<class CRTP>
         struct add_op_type
         {
            using add_tag = add_op_type;
            protected:

               /* suggests that std::string is used for the box_type */
               template<typename D=CRTP, typename BOX=typename D::box_type,typename std::enable_if<std::is_pod<typename BOX::value_type>::value>::type* = nullptr, class... Args>
               inline auto operator()(Args&&... args) 
                  -> decltype(std::declval<BOX>().append(args...)) {
                     return traits::selfie<D>(this)->box.append(std::forward< Args >(args)...);
               }
               /* maps insert */
               template<typename D=CRTP,typename BOX=typename D::box_type, typename std::enable_if<traits::is_pair<typename BOX::value_type>::value>::type* = nullptr>
               inline auto operator()(typename BOX::value_type&& v) 
                  -> decltype(std::declval<BOX>().insert(v)){
                     return traits::selfie<D>(this)->box.insert(std::forward< typename BOX::value_type >(v));
               }
               /* sets insert */
               template<typename D=CRTP,typename BOX=typename D::box_type, typename std::enable_if<std::is_same<typename BOX::key_type,typename BOX::value_type>::value   >::type* = nullptr >
               inline auto operator()(typename BOX::key_type&& key) 
                  -> decltype(std::declval<BOX>().insert(key)){
                     return traits::selfie<D>(this)->box.insert(std::forward< BOX::key_type >(key));
               }
               /* generic emplace */
               template<typename D=CRTP,typename BOX=typename D::box_type, class... Args >
               inline auto operator()(Args&&... args) 
                  -> decltype(std::declval<BOX>().emplace(args...)){
                     return traits::selfie<D>(this)->box.emplace(std::forward< Args >(args)...);
               }
         }; /* add_op_type template */

         /**
          * @template del_op_type
          * @abstract A universal del_tag functor.
          * This template is compatible with the crtp_mixin_type.
          */
         template<class CRTP>
         struct del_op_type{
            using del_tag=del_op_type;
            protected:
               template<typename D=CRTP,typename BOX=typename D::box_type, class... Args >
               inline auto operator()(Args&&... args) 
                  -> decltype(std::declval<BOX>().erase(args...)){
                     return traits::selfie<D>(this)->box.erase(std::forward< Args >(args)...);
               }
         }; /* del_op_type template */

         /**
          * @template find_op_type
          * @abstract A universal find_tag functor.
          * This template is compatible with the crtp_mixin_type.
          */
         template<class CRTP>
         struct find_op_type{
            using find_tag=find_op_type;
            protected:
               template<typename D=CRTP,typename BOX=typename D::box_type, class... Args >
               inline auto operator()(Args&&... args) const noexcept
                  -> decltype(std::declval<BOX>().find(args...)){
                     return traits::selfie<D>(this)->box.find(std::forward< Args >(args)...);
               }
         }; /* find_op_type */

         /**
          * @template out_op_type
          * @abstract A universal out_tag functor. 
          * This template is compatible with the crtp_mixin_type.
          */
         template<class CRTP>
         struct out_op_type{
            using out_tag=out_op_type;
            protected:
               template<typename D=CRTP>
               inline std::ostream& operator()(std::ostream & out,const D & obj ) const noexcept{
                  return ((out<<traits::selfie<D,out_tag>(obj).box));
               }
         }; /* out_op_type template */

         /**
          * @template size_op_type
          * @abstract A universal size_tag functor. 
          * This template is compatible with the crtp_mixin_type.
          */
         template<class CRTP>
         struct size_op_type{
            using size_tag=size_op_type;
            protected:
               template<typename D=CRTP,typename BOX=typename D::box_type, class... Args >
               inline auto operator()(Args&&... args) const noexcept
                  -> decltype(std::declval<BOX>().size(args...)){
                     return traits::selfie<D>(this)->box.size(std::forward< Args >(args)...);
               }
         }; /* size_op_type template */

         /**
          * @template count_op_type
          * @abstract A universal count_tag functor. 
          * This template is compatible with the crtp_mixin_type.
          */
         template<class CRTP>
         struct count_op_type{
            using count_tag=count_op_type;
            protected:
               template<typename D=CRTP,typename BOX=typename D::box_type, class... Args >
               inline auto operator()(Args&&... args) const noexcept
                  -> decltype(std::declval<BOX>().count(args...)){
                     return traits::selfie<D>(this)->box.count(std::forward< Args >(args)...);
               }
         }; /* size_op_type template */

         /**
          * @template clear_op_type
          * @abstract A universal clear_tag functor.
          * This template is compatible with the crtp_mixin_type.
          */
         template<class CRTP>
         struct clear_op_type{
            using clear_tag=clear_op_type;
            protected:
               template<typename D=CRTP,typename BOX=typename D::box_type, class... Args >
               inline auto operator()(Args&&... args) noexcept 
                  -> decltype(std::declval<BOX>().clear(args...)){
                     return traits::selfie<D>(this)->box.clear(std::forward< Args >(args)...);
               }
         }; /* clear_op_type template */

         /**
          * @template reset_op_type
          * @abstract A universal reset_tag functor.
          * This template is compatible with the crtp_mixin_type.
          */
         template<class CRTP>
         struct reset_op_type{
            using reset_tag=reset_op_type;
            protected:
               template<typename D=CRTP,typename BOX=typename D::box_type, class... Args >
               inline auto operator()(Args&&... args) 
                  -> decltype(std::declval<BOX>().reset(args...)){
                     return traits::selfie<D>(this)->box.reset(std::forward< Args >(args)...);
               }
         }; /* clear_op_type template */

         /**
          * @template subscript_op_type
          * @abstract A universal subscript_tag functor.
          * This template is compatible with the crtp_mixin_type.
          */
         template<class CRTP>
         struct subscript_op_type{
            using subscript_tag=subscript_op_type;
            protected:
               template<typename D=CRTP,typename BOX=typename D::box_type,  class... Args >
               inline auto operator()(Args&&... args) 
                  -> decltype(std::declval<BOX>().operator[](args...)){
                     return traits::selfie<D>(this)->box.operator[](std::forward< Args >(args)...);
               }
         }; /* subscript_op_type template */


         /**
          * @template std_box_type
          * @abstract an example of fully implemented box_type
          *
          */
         template<typename BOX>
         using std_box_type = box_type<BOX,add_op_type,out_op_type,size_op_type,count_op_type,
                              find_op_type,del_op_type,clear_op_type,subscript_op_type>;

         /**
          * @template flat_lock_box
          * @abstract 
          */   
         template <class BOX>
         struct flat_lock_box
         {
            using box_type = BOX;
            using value_type = typename box_type::value_type;

            /* inner box */
            BOX box_{};
            /* inner lock */
            mutable std::mutex lock_{};

            /* flatining interface */
            template <typename... Args>
            inline auto insert(Args&&... args) 
                -> decltype (box_.insert(args...)){
               std::lock_guard<std::mutex> mlock{lock_};
               return box_.insert(std::forward<Args>(args)...);
            }

            template <typename... Args>
            inline auto emplace(Args&&... args) 
                -> decltype (box_.emplace(args...)){
               std::lock_guard<std::mutex> mlock{lock_};
               return box_.emplace(std::forward<Args>(args)...);
            }

            template <typename... Args>
            inline auto find(Args&&... args) const noexcept
                -> decltype (box_.find(args...)) const {
               std::lock_guard<std::mutex> mlock{lock_};
               return box_.find(std::forward<Args>(args)...);
            }

            inline auto end() noexcept
               -> decltype(box_.end()) {
               return box_.end();
            }

            inline auto end() const noexcept
               -> decltype(box_.end()) {
               return box_.end();
            }

            inline auto cend() const noexcept
               -> decltype(box_.cend()) {
               return box_.cend();
            }

            inline auto begin() noexcept
               -> decltype(box_.begin()) {
               return box_.begin();
            }

            inline auto begin() const noexcept
               -> decltype(box_.begin()) {
               return box_.begin();
            }

            inline auto cbegin() const noexcept 
               -> decltype(box_.cbegin()) {
               return box_.cbegin();
            }

            inline auto clear() noexcept 
                -> decltype (box_.clear())  {
               std::lock_guard<std::mutex> mlock{lock_};
               return box_.clear();
            }

            inline auto size() const noexcept 
                -> decltype (box_.size())  {
               std::lock_guard<std::mutex> mlock{lock_};
               return box_.size();
            }

            /**
             * @note generally, a call to the count() without an argument 
             *       is to be considered as an equivalent call to the size()
             */
            inline auto count(/*no arg*/) const noexcept 
                -> decltype (box_.size())  {
               std::lock_guard<std::mutex> mlock{lock_};
               return box_.size();
            }

         };

      }; /* crtps namespace */

   }; /* tools namespace */

}; /* titan_v3 namespace */

#endif /* TTN_CRTPS_HXX */

