/*  =========================================================================
    asset_database - Asset database singleton

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

#ifndef ASSET_DATABASE_H_INCLUDED
#define ASSET_DATABASE_H_INCLUDED

#include <memory>
#include <map>
#include <stdexcept>

// force proper header order
#include "database.h"
#include "asset.h"

#include "fty_alert_engine_classes.h"

/*
 * \brief Class that provides C++ singleton database of assets
 */
template <typename AssetT>
class AssetDatabase : public ObservedGenericDatabase<std::string, std::shared_ptr<AssetT>> {
    private:
        using OGD = ObservedGenericDatabase<std::string, std::shared_ptr<AssetT>>;
        using GD = GenericDatabase<std::string, std::shared_ptr<AssetT>>;
    public:
        // delete old Element-based interface
        std::shared_ptr<AssetT> getElementForManipulation (const std::string key) = delete;
        const std::shared_ptr<AssetT> getElement (const std::string key) = delete;
        void insertElement (std::string, AssetT) = delete;
        void insertElement (std::string, std::shared_ptr<AssetT>) = delete;
        void updateElement (std::string, AssetT) = delete;
        void updateElement (std::string, std::shared_ptr<AssetT>) = delete;
        void insertOrUpdateElement (std::string, AssetT) = delete;
        void insertOrUpdateElement (std::string, std::shared_ptr<AssetT>) = delete;
        void deleteElement (std::string key) = delete;
        // provide more asset-oriented interface
        std::shared_ptr<AssetT> getAssetForManipulation (const std::string key) {
            return OGD::getElementForManipulation (key);
        }
        const std::shared_ptr<AssetT> getAsset (const std::string key) {
            return OGD::getElement (key);
        }
        void insertAsset (AssetT asset) {
            OGD::insertElement (static_cast<BasicAsset>(asset).getId (), std::make_shared<AssetT>(asset));
        };
        void insertAsset (std::string key, std::shared_ptr<AssetT> asset) {
            if (asset != nullptr) {
                OGD::insertElement (
                        static_cast<std::shared_ptr<BasicAsset>>(asset)->getId (), asset);
            } else {
                throw null_argument ();
            }
        };
        void updateAsset (AssetT asset) {
            OGD::updateElement (static_cast<BasicAsset>(asset).getId (), std::make_shared<AssetT>(asset));
        }
        void updateAsset (std::shared_ptr<AssetT> asset) {
            if (asset != nullptr) {
                OGD::updateElement (
                        static_cast<std::shared_ptr<BasicAsset>>(asset)->getId (), asset);
            } else {
                throw null_argument ();
            }
        }
        void insertOrUpdateAsset (AssetT asset) {
            OGD::insertOrUpdateElement (static_cast<BasicAsset>(asset).getId (), std::make_shared<AssetT>(asset));
        }
        void insertOrUpdateAsset (std::shared_ptr<AssetT> asset) {
            if (asset != nullptr) {
                OGD::insertOrUpdateElement (
                        static_cast<std::shared_ptr<BasicAsset>>(asset)->getId (), asset);
            } else {
                throw null_argument ();
            }
        }
        void deleteAsset (std::string key) {
            OGD::deleteElement (key);
        }
    public:
        // need to republish iterators, otherwise they are inacessible
        inline typename std::map<std::string, std::shared_ptr<AssetT>>::iterator begin () noexcept {
            return OGD::begin ();
        }
        inline typename std::map<std::string, std::shared_ptr<AssetT>>::const_iterator cbegin () const noexcept {
            return OGD::cbegin ();
        }
        inline typename std::map<std::string, std::shared_ptr<AssetT>>::iterator end () noexcept {
            return OGD::end ();
        }
        inline typename std::map<std::string, std::shared_ptr<AssetT>>::const_iterator cend () const noexcept {
            return OGD::cend ();
        }
};

template <typename TypeT>
class Singleton {
    private:
        // ctor
        Singleton () { };
    public:
        // ctors, =, instantiation
        Singleton (const Singleton &ad) = delete;
        Singleton (Singleton &&ad) = delete;
        Singleton & operator= (const Singleton &ad) = delete;
        Singleton & operator= (Singleton &&ad) = delete;
        static TypeT & getInstance () {
            static TypeT singleton;
            return singleton;
        }
};

template class Singleton<AssetDatabase<BasicAsset>>;
template class Singleton<AssetDatabase<ExtendedAsset>>;
template class Singleton<AssetDatabase<FullAsset>>;
// specialized types of asset databases
using BasicAssetDatabase = Singleton<AssetDatabase<BasicAsset>>;
using ExtendedAssetDatabase = Singleton<AssetDatabase<ExtendedAsset>>;
using FullAssetDatabase = Singleton<AssetDatabase<FullAsset>>;
// nice names
using BasicAssetSPtr = std::shared_ptr<BasicAsset>;
using ExtendedAssetSPtr = std::shared_ptr<ExtendedAsset>;
using FullAssetSPtr = std::shared_ptr<FullAsset>;

#endif
