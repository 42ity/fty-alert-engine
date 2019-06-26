/*  =========================================================================
    database - Database

    Copyright (C) 2019 - 2019 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

#ifndef DATABASE_H_INCLUDED
#define DATABASE_H_INCLUDED

#include <memory>
#include <map>
#include <stdexcept>
#include <functional>

#include "fty_alert_engine_classes.h"

class null_argument : public std::runtime_error {
    public:
        null_argument () : runtime_error ("null argument") { }
};
class element_exists: public std::runtime_error {
    public:
        element_exists () : runtime_error ("element already exist") { }
};
class element_not_found : public std::runtime_error {
    public:
        element_not_found () : runtime_error ("element not found") { }
};

/*
 * \brief Class that provides simple in-memory database
 */
template <typename KeyT, typename ElementT>
class GenericDatabase {
    public:
        using DatabaseType = std::map<KeyT, ElementT>;
        using iterator = typename DatabaseType::iterator;
        using const_iterator = typename DatabaseType::const_iterator;
    private:
        /// database implementation, indexed by some key
        DatabaseType database_;
    protected:
        /// accessor
        iterator getElementIt (const KeyT &key) {
            return database_.find (key);
        }
        const_iterator getElementIt (const KeyT &key) const {
            return database_.find (key);
        }
    public:
        // ctors, =, instantiation
        GenericDatabase () { };
        GenericDatabase (const GenericDatabase & ad) = delete;
        GenericDatabase (GenericDatabase && ad) = delete;
        GenericDatabase & operator= (const GenericDatabase &ad) = delete;
        GenericDatabase & operator= (GenericDatabase &&ad) = delete;
        // data manipulation
        /// getter for possible updates, user needs to check unique () to ensure at least basic thread safety
        ElementT getElementForManipulation (const KeyT key) {
            iterator it = getElementIt (key);
            if (it != database_.end ()) {
                return getElementIt (key)->second;
            } else {
                throw element_not_found ();
            }
        }
        /// getter for data extraction
        const ElementT getElement (const KeyT key) const {
            const_iterator it = getElementIt (key);
            if (it != database_.end ()) {
                return getElementIt (key)->second;
            }
            throw element_not_found ();
        }
        void insertOrUpdateElement (const KeyT key, const ElementT element) {
            database_[key] = element;
        }
        void deleteElement (const KeyT key) {
            iterator it = getElementIt (key);
            if (it != database_.end ()) {
                database_.erase (getElementIt (key));
            } else {
                throw element_not_found ();
            }
        }
        void clear () {
            database_.clear ();
        }
        // iterators
        inline typename std::map<KeyT, ElementT>::iterator begin () noexcept { return database_.begin (); }
        inline typename std::map<KeyT, ElementT>::const_iterator cbegin () const noexcept { return database_.cbegin (); }
        inline typename std::map<KeyT, ElementT>::iterator end () noexcept { return database_.end (); }
        inline typename std::map<KeyT, ElementT>::const_iterator cend () const noexcept { return database_.cend (); }
};

/*
 * \brief Class that provides simple in-memory observed database
 */
template <typename KeyT, typename ElementT>
class ObservedGenericDatabase : public GenericDatabase<KeyT, ElementT> {
    using GD = GenericDatabase<KeyT,ElementT>;
    using GD::end;
    public:
        using CallbackFunction = std::function<void (const ElementT)>;
    private:
        CallbackFunction on_create;
        CallbackFunction on_update;
        CallbackFunction on_delete;
        bool on_update_only_different;
    public:
        // observer manipulation
        void setOnCreate (CallbackFunction f) { on_create = f; }
        void setOnUpdate (CallbackFunction f) { on_update = f; on_update_only_different = false; }
        void setOnDelete (CallbackFunction f) { on_delete = f; }
        void clearOnCreate () { on_create = CallbackFunction (); }
        void clearOnUpdate () { on_update = CallbackFunction (); on_update_only_different = false; }
        void clearOnDelete () { on_delete = CallbackFunction (); }
        void setOnUpdateOnlyOnDifference (bool on_diff) { on_update_only_different = on_diff; }
        // calls
        /// throws any errors, notably element_not_found
        void insertElement (KeyT key, ElementT element) {
            if (GD::getElementIt (key) != end ()) {
                throw element_exists ();
            }
            GD::insertOrUpdateElement (key, element);
            if (on_create) {
                ElementT e = this->getElement (key);
                on_create (e);
            }
        }
        /// throws any errors, notably element_not_found
        void updateElement (KeyT key, ElementT element) {
            if (GD::getElementIt (key) == end ()) {
                throw element_not_found ();
            }
            const ElementT e = this->getElement (key);
            GD::insertOrUpdateElement (key, element);
            if (on_update) {
                if (!on_update_only_different || e == element) {
                    ElementT ee = this->getElement (key);
                    on_update (ee);
                }
            }
        }
        void insertOrUpdateElement (KeyT key, ElementT element) {
            if (GD::getElementIt (key) != end ()) {
                // update
                updateElement (key, element);
            } else {
                // insert
                insertElement (key, element);
            }
        }
        /// throws any errors, notably element_not_found
        void deleteElement (KeyT key) {
            const ElementT e = GD::getElement (key);
            GD::deleteElement (key);
            if (on_delete)
                on_delete (e);
        }
        void clear () {
            GD::clear ();
            on_create = nullptr;
            on_update = nullptr;
            on_delete = nullptr;
        }
    public:
        // need to republish iterators, otherwise they are inacessible
        inline typename std::map<std::string, ElementT>::iterator begin () noexcept { return GD::begin (); }
        inline typename std::map<std::string, ElementT>::const_iterator cbegin () const noexcept { return GD::cbegin (); }
        inline typename std::map<std::string, ElementT>::iterator end () noexcept { return GD::end (); }
        inline typename std::map<std::string, ElementT>::const_iterator cend () const noexcept { return GD::cend (); }
};

#endif
