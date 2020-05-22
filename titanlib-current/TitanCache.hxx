/*
 * $Id$
 *
 */

#ifndef TITANCACHE_H_
#define TITANCACHE_H_

#include <cassert>
#include <map>
#include <string>
#include <mutex>
#include <queue>
#include <ctime>
#include <functional>
#include <iostream>
#include <atomic>

template<class T>
class TitanCache {
private:
   enum status_t {
      empty=0x00,
      locked,
      reserved,
      used,
      old
   };

   std::mutex              mgmt_mtx{};
   using released_t = std::queue<size_t>;
   released_t              released{};
   std::mutex              sync_mtx{};
   std::queue<T>           pending_sync{};

   struct t_elements {
      T                     element{};
      std::mutex            elem_mtx{};
      std::atomic<bool>     updated{};
      time_t                expiration_time{};
      status_t              status{empty};
   };

   t_elements*             elements{};
   size_t                  next_candidate{};
   size_t                  size{};
protected:

   virtual void resetElement(T& element) = 0;

   virtual void deleteActions(T& element) = 0;

public:
   explicit TitanCache(const size_t sz) noexcept : elements{new t_elements[sz]}, size{sz} {}
   virtual ~TitanCache() {
      if ( elements )
         delete[] elements;
   } 

   size_t addElement(const T& new_elem, const bool do_not_delete = false);

   bool copyElement(const size_t index, T& copy_buffer) noexcept ;

   void updateElement(const size_t index, std::function<void(T&)> updateActions);

   void updateAllElements(std::function<void(T&)> updateActions);

   void deleteElement(const size_t index);

   bool readUpdatedElements(std::function<void(T&)> readActions, size_t remaining, size_t* const next);

   void reloadCache();
};

template<class T>
size_t TitanCache<T>::addElement(   const T& new_elem, 
                                    const bool do_not_delete)  {
   size_t index{} ;
   bool reset_elem{} ;
   assert ( elements );

   {  /* locking scope */
      std::unique_lock<std::mutex> mgmt_lock(mgmt_mtx);

      //Check first if some slot has been released.
      if (released.size()) {
         index = released.front();
         released.pop();
         if (next_candidate == index) {
            next_candidate = (next_candidate + 1) % size;
         }
      }
      else {
         //Apply the clock swap algorithm.
         bool found{} ;
         while (!found) {
            std::lock_guard<std::mutex> elem_lock{elements[next_candidate].elem_mtx};
            switch (elements[next_candidate].status) {
                case old:
                   if (elements[next_candidate].updated) {
                      std::lock_guard<std::mutex> sync_lock{sync_mtx};
                      T elem_store = elements[next_candidate].element;
                      elements[next_candidate].updated = false;
                      pending_sync.push(elem_store);
                   }
                   reset_elem = true;
                   [[clang::fallthrough]];
                case empty:
                   found = true;
                   elements[next_candidate].status = reserved;
                   index = next_candidate;
                   break;
                case used:
                   elements[next_candidate].status = old;
                   break;
                default:
                   break;
            }
            next_candidate = (next_candidate + 1) % size;
         }
      }

   }


   if (reset_elem) {
      deleteActions(elements[index].element);
   }

   std::lock_guard<std::mutex> elem_lock{elements[index].elem_mtx};

   if (reset_elem) {
      resetElement(elements[index].element);
   }
   elements[index].element = new_elem;

   if (do_not_delete) {
      elements[index].status = locked;
   }
   else {
      elements[index].status = used;
   }

   return index;
}

template<class T>
bool TitanCache<T>::copyElement(    const size_t index, 
                                    T& copy_buffer) noexcept  {
    if (index < size) {
        assert ( elements ); 
        std::lock_guard<std::mutex> lg{elements[index].elem_mtx};
        switch (elements[index].status){
            case status_t::empty:
            case status_t::reserved: break;
            default:{
                copy_buffer = elements[index].element;
                if (elements[index].status == old) {
                    elements[index].status = used;
                }
                return true;
            }
        }
    }
    return false;
}

template<class T>
void TitanCache<T>::deleteElement(const size_t index) {
   if (index < size) {
      assert ( elements ); 
      deleteActions(elements[index].element);

      #if ( ( __FreeBSD_version >= MIN_OS_FB_11 ) || ! defined ( __clang_analyzer__ ) )
      std::unique_lock<std::mutex> e_lock{elements[index].elem_mtx,std::defer_lock};
      std::unique_lock<std::mutex> m_lock{mgmt_mtx,std::defer_lock};
      std::lock(e_lock,m_lock); // can throw an exception
      #endif
      resetElement(elements[index].element);
      elements[index].status = empty;

      /*
       * if called multiple times with the same id,
       * could cause a temporary memory leak (until reload)
       */
      released.push(index);
   }
}

template<class T>
void TitanCache<T>::updateElement(  const size_t index, 
                                    std::function<void(T&)> updateActions) {
    if (index < size) {
        assert ( elements ); 
        std::lock_guard<std::mutex> lg{elements[index].elem_mtx};
        switch (elements[index].status){
            case status_t::empty:
            case status_t::reserved: break;
            default:{
                 updateActions(elements[index].element);
                 if (elements[index].status == old) {
                    elements[index].status = used;
                 }
                 elements[index].updated = true;
            } break;
        }
    }
}


template<class T>
void TitanCache<T>::updateAllElements(std::function<void(T&)> updateActions) {
    assert ( elements ); 
    for (size_t i = 0; i < size; ++i) {
        std::lock_guard<std::mutex> lg{elements[i].elem_mtx};
        switch (elements[i].status){
            case status_t::empty:
            case status_t::reserved: continue;
            default:{
                updateActions(elements[i].element);
                elements[i].updated = true;
            }
        }
    }
}

template<class T>
bool TitanCache<T>::readUpdatedElements(    std::function<void(T&)> readActions, 
                                            size_t remaining,
                                            size_t* const next) {

   size_t index{};
   if (next != nullptr) {
      index = *next;
   }

   assert ( elements ); 
   while (index < size) {
      std::lock_guard<std::mutex> lg{elements[index].elem_mtx};
      if (elements[index].updated) {
         readActions(elements[index].element);
         elements[index].updated = false;
         if (--remaining == 0) {
            if (next)
               *next = index;

            return false;
         }
      }
      ++index;
   }

   if (remaining) {
      std::lock_guard<std::mutex> lg{sync_mtx};
      while (!pending_sync.empty()) {
         T elem = pending_sync.front();
         pending_sync.pop();
         readActions(elem);
         if (--remaining == 0) {
            if (next)
               *next = size;

            return false;
         }
      }
   }

   return true;
}

template<class T>
void TitanCache<T>::reloadCache() {
   assert ( elements ); 

   std::unique_lock<std::mutex> m_lock{mgmt_mtx};

   for (size_t i = 0;i < size; ++i) {
      deleteActions(elements[i].element);
      std::unique_lock<std::mutex> e_lock{elements[i].elem_mtx};
      resetElement(elements[i].element);
      elements[i].status = empty;
   }

   /* clean it to prevent a memory leak */
   released_t empty{};
   std::swap( empty , released );
}


#endif /* TITANCACHE_H_ */

/* vim: set ts=4 sw=4 et : */
