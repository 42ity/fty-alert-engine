/*  =========================================================================
    asset - Asset class

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

/*
@header
    asset - Asset class
@discuss
@end
*/

#include <string>

#include "fty_alert_engine_classes.h"

std::string BasicAsset::typeToString (BasicAsset::Type type) const {
    switch (type) {
        case Type_Cluster:
            return "cluster";
        case Type_Datacenter:
            return "datacenter";
        case Type_Device:
            return "device";
        case Type_Group:
            return "group";
        case Type_Hypervisor:
            return "hypervisor";
        case Type_Rack:
            return "rack";
        case Type_Room:
            return "room";
        case Type_Row:
            return "row";
        case Type_Storage:
            return "storage";
        case Type_VApp:
            return "vapp";
        case Type_VirtuService:
            return "virtuservice";
        case Type_VM:
            return "vm";
        default:
            throw std::invalid_argument ("type is not known value");
    }
}

BasicAsset::Type BasicAsset::stringToType (std::string type) const {
    if (type == "cluster") {
        return Type_Cluster;
    } else if (type == "datacenter") {
        return Type_Datacenter;
    } else if (type == "device") {
        return Type_Device;
    } else if (type == "group") {
        return Type_Group;
    } else if (type == "hypervisor") {
        return Type_Hypervisor;
    } else if (type == "rack") {
        return Type_Rack;
    } else if (type == "room") {
        return Type_Room;
    } else if (type == "row") {
        return Type_Row;
    } else if (type == "storage") {
        return Type_Storage;
    } else if (type == "vapp") {
        return Type_VApp;
    } else if (type == "virtuservice") {
        return Type_VirtuService;
    } else if (type == "vm") {
        return Type_VM;
    } else {
        throw std::invalid_argument ("type is not known value");
    }
}

std::string BasicAsset::subtypeToString (BasicAsset::Subtype subtype) const {
    switch (subtype) {
        case Subtype_Appliance:
            return "appliance";
        case Subtype_Chassis:
            return "chassis";
        case Subtype_CitrixPool:
            return "citrixpool";
        case Subtype_CitrixTask:
            return "citrixtask";
        case Subtype_CitrixVApp:
            return "citrixvapp";
        case Subtype_CitrixVM:
            return "citrixvm";
        case Subtype_CitrixXenserver:
            return "citrixxenserver";
        case Subtype_EPDU:
            return "epdu";
        case Subtype_Feed:
            return "feed";
        case Subtype_Genset:
            return "genset";
        case Subtype_GPO:
            return "gpo";
        case Subtype_HPITManager:
            return "hpitmanager";
        case Subtype_HPITManagerService:
            return "hpitmanagerservice";
        case Subtype_HPITRack:
            return "hpitrack";
        case Subtype_HPITServer:
            return "hpitserver";
        case Subtype_IPMInfraServer:
            return "ipminfraserver";
        case Subtype_IPMInfraService:
            return "ipminfraservice";
        case Subtype_MicrosoftCluster:
            return "microsoftcluster";
        case Subtype_MicrosoftHyperV:
            return "microsofthyperv";
        case Subtype_MicrosoftServer:
            return "microsoftserver";
        case Subtype_MicrosoftTask:
            return "microsofttask";
        case Subtype_MicrosoftVirtualizationMachine:
            return "microsoftvirtualizationmachine";
        case Subtype_MicrosoftVM:
            return "microsoftvm";
        case Subtype_MicrosoftWindowsServer:
            return "microsoftwindowsserver";
        case Subtype_NetAppCluster:
            return "netappcluster";
        case Subtype_NetAppNode:
            return "netappnode";
        case Subtype_NetAppOntapNode:
            return "netappontapnode";
        case Subtype_NetAppOntapSystem:
            return "netappontapsystem";
        case Subtype_NetAppServer:
            return "netappserver";
        case Subtype_NutanixCluster:
            return "nutanixcluster";
        case Subtype_NutanixNode:
            return "nutanixnode";
        case Subtype_NutanixPrismGateway:
            return "nutanixprismgateway";
        case Subtype_NutanixVirtualizationMachine:
            return "nutanixvirtualizationmachine";
        case Subtype_N_A:
            return "n_a";
        case Subtype_Other:
            return "other";
        case Subtype_PatchPanel:
            return "patchpanel";
        case Subtype_PDU:
            return "pdu";
        case Subtype_RackController:
            return "rackcontroller";
        case Subtype_Router:
            return "router";
        case Subtype_Sensor:
            return "sensor";
        case Subtype_SensorGPIO:
            return "sensorgpio";
        case Subtype_Server:
            return "server";
        case Subtype_Storage:
            return "storage";
        case Subtype_STS:
            return "sts";
        case Subtype_Switch:
            return "switch";
        case Subtype_UPS:
            return "ups";
        case Subtype_VM:
            return "vm";
        case Subtype_VMWareCluster:
            return "vmwarecluster";
        case Subtype_VMWareESXI:
            return "vmwareesxi";
        case Subtype_VMWareStandaloneESXI:
            return "vmwarestandaloneesxi";
        case Subtype_VMWareTask:
            return "vmwaretask";
        case Subtype_VMWareVApp:
            return "vmwarevapp";
        case Subtype_VMWareVCenter:
            return "vmwarevcenter";
        case Subtype_VMWareVM:
            return "vmwarevm";
        default:
            throw std::invalid_argument ("subtype is not known value");
    }
}

BasicAsset::Subtype BasicAsset::stringToSubtype (std::string subtype) const {
    if (subtype == "appliance") {
        return Subtype_Appliance;
    } else if (subtype == "chassis") {
        return Subtype_Chassis;
    } else if (subtype == "citrixpool") {
        return Subtype_CitrixPool;
    } else if (subtype == "citrixtask") {
        return Subtype_CitrixTask;
    } else if (subtype == "citrixvapp") {
        return Subtype_CitrixVApp;
    } else if (subtype == "citrixvm") {
        return Subtype_CitrixVM;
    } else if (subtype == "citrixxenserver") {
        return Subtype_CitrixXenserver;
    } else if (subtype == "epdu") {
        return Subtype_EPDU;
    } else if (subtype == "feed") {
        return Subtype_Feed;
    } else if (subtype == "genset") {
        return Subtype_Genset;
    } else if (subtype == "gpo") {
        return Subtype_GPO;
    } else if (subtype == "hpitmanager") {
        return Subtype_HPITManager;
    } else if (subtype == "hpitmanagerservice") {
        return Subtype_HPITManagerService;
    } else if (subtype == "hpitrack") {
        return Subtype_HPITRack;
    } else if (subtype == "hpitserver") {
        return Subtype_HPITServer;
    } else if (subtype == "ipminfraserver") {
        return Subtype_IPMInfraServer;
    } else if (subtype == "ipminfraservice") {
        return Subtype_IPMInfraService;
    } else if (subtype == "microsoftcluster") {
        return Subtype_MicrosoftCluster;
    } else if (subtype == "microsofthyperv") {
        return Subtype_MicrosoftHyperV;
    } else if (subtype == "microsoftserver") {
        return Subtype_MicrosoftServer;
    } else if (subtype == "microsofttask") {
        return Subtype_MicrosoftTask;
    } else if (subtype == "microsoftvirtualizationmachine") {
        return Subtype_MicrosoftVirtualizationMachine;
    } else if (subtype == "microsoftvm") {
        return Subtype_MicrosoftVM;
    } else if (subtype == "microsoftwindowsserver") {
        return Subtype_MicrosoftWindowsServer;
    } else if (subtype == "netappcluster") {
        return Subtype_NetAppCluster;
    } else if (subtype == "netappnode") {
        return Subtype_NetAppNode;
    } else if (subtype == "netappontapnode") {
        return Subtype_NetAppOntapNode;
    } else if (subtype == "netappontapsystem") {
        return Subtype_NetAppOntapSystem;
    } else if (subtype == "netappserver") {
        return Subtype_NetAppServer;
    } else if (subtype == "nutanixcluster") {
        return Subtype_NutanixCluster;
    } else if (subtype == "nutanixnode") {
        return Subtype_NutanixNode;
    } else if (subtype == "nutanixprismgateway") {
        return Subtype_NutanixPrismGateway;
    } else if (subtype == "nutanixvirtualizationmachine") {
        return Subtype_NutanixVirtualizationMachine;
    } else if (subtype == "n_a") {
        return Subtype_N_A;
    } else if (subtype == "other") {
        return Subtype_Other;
    } else if (subtype == "patchpanel") {
        return Subtype_PatchPanel;
    } else if (subtype == "pdu") {
        return Subtype_PDU;
    } else if (subtype == "rackcontroller") {
        return Subtype_RackController;
    } else if (subtype == "router") {
        return Subtype_Router;
    } else if (subtype == "sensor") {
        return Subtype_Sensor;
    } else if (subtype == "sensorgpio") {
        return Subtype_SensorGPIO;
    } else if (subtype == "server") {
        return Subtype_Server;
    } else if (subtype == "storage") {
        return Subtype_Storage;
    } else if (subtype == "sts") {
        return Subtype_STS;
    } else if (subtype == "switch") {
        return Subtype_Switch;
    } else if (subtype == "ups") {
        return Subtype_UPS;
    } else if (subtype == "vm") {
        return Subtype_VM;
    } else if (subtype == "vmwarecluster") {
        return Subtype_VMWareCluster;
    } else if (subtype == "vmwareesxi") {
        return Subtype_VMWareESXI;
    } else if (subtype == "vmwarestandaloneesxi") {
        return Subtype_VMWareStandaloneESXI;
    } else if (subtype == "vmwaretask") {
        return Subtype_VMWareTask;
    } else if (subtype == "vmwarevapp") {
        return Subtype_VMWareVApp;
    } else if (subtype == "vmwarevcenter") {
        return Subtype_VMWareVCenter;
    } else if (subtype == "vmwarevm") {
        return Subtype_VMWareVM;
    } else {
        throw std::invalid_argument ("subtype is not known value");
    }
}

std::string BasicAsset::statusToString (BasicAsset::Status status) const {
    switch (status) {
        case Status::Active:
            return "active";
        case Status::Nonactive:
            return "nonactive";
        default:
            throw std::invalid_argument ("status is not known value");
    }
}

BasicAsset::Status BasicAsset::stringToStatus (std::string status) const {
    if (status == "active") {
        return Status::Active;
    } else if (status == "nonactive") {
        return Status::Nonactive;
    } else {
        throw std::invalid_argument ("status is not known value");
    }
}

bool BasicAsset::compare (const BasicAsset &asset) const {
    return id_ == asset.id_ && status_ == asset.status_ && type_subtype_ == asset.type_subtype_;
}

bool ExtendedAsset::compare (const ExtendedAsset &asset) const {
    return BasicAsset::compare (asset) && name_ == asset.name_ && parent_id_ == asset.parent_id_ &&
        priority_ == asset.priority_;
}

void ExtendedAsset::setPriority (const std::string priority) {
    priority_ = priority[1] - '0';
}

bool FullAsset::compare (const FullAsset &asset) const {
    return ExtendedAsset::compare (asset) && aux_ == asset.aux_ && ext_ == asset.ext_;
}

std::string FullAsset::getAuxItem (const std::string &key) const {
    auto it = aux_.find (key);
    if (it != aux_.end ()) {
        return it->second;
    }
    return std::string ();
}

std::string FullAsset::getExtItem (const std::string &key) const {
    auto it = ext_.find (key);
    if (it != ext_.end ()) {
        return it->second;
    }
    return std::string ();
}

std::string FullAsset::getItem (const std::string &key) const {
    auto it = ext_.find (key);
    if (it != ext_.end ()) {
        return it->second;
    } else {
        auto it2 = aux_.find (key);
        if (it2 != aux_.end ()) {
            return it2->second;
        }
    }
    return std::string ();
}

std::unique_ptr<BasicAsset> getBasicAssetFromFtyProto (fty_proto_t *msg) {
    if (fty_proto_id (msg) != FTY_PROTO_ASSET)
        throw std::invalid_argument ("Wrong fty-proto type");
    return std::unique_ptr<BasicAsset>(new BasicAsset (
        fty_proto_name (msg),
        fty_proto_aux_string (msg, "status", "active"),
        fty_proto_aux_string (msg, "type", ""),
        fty_proto_aux_string (msg, "subtype", "")));
}

std::unique_ptr<ExtendedAsset> getExtendedAssetFromFtyProto (fty_proto_t *msg) {
    if (fty_proto_id (msg) != FTY_PROTO_ASSET)
        throw std::invalid_argument ("Wrong fty-proto type");
    return std::unique_ptr<ExtendedAsset>(new ExtendedAsset (
        fty_proto_name (msg),
        fty_proto_aux_string (msg, "status", "active"),
        fty_proto_aux_string (msg, "type", ""),
        fty_proto_aux_string (msg, "subtype", ""),
        fty_proto_ext_string (msg, "name", fty_proto_name (msg)),
        fty_proto_aux_string (msg, "parent_name.1", ""),
        fty_proto_aux_number (msg, "priority", 5)));
}

std::unique_ptr<FullAsset> getFullAssetFromFtyProto (fty_proto_t *msg) {
    if (fty_proto_id (msg) != FTY_PROTO_ASSET)
        throw std::invalid_argument ("Wrong fty-proto type");
    return std::unique_ptr<FullAsset>(new FullAsset (
        fty_proto_name (msg),
        fty_proto_aux_string (msg, "status", "active"),
        fty_proto_aux_string (msg, "type", ""),
        fty_proto_aux_string (msg, "subtype", ""),
        fty_proto_ext_string (msg, "name", fty_proto_name (msg)),
        fty_proto_aux_string (msg, "parent_name.1", ""),
        fty_proto_aux_number (msg, "priority", 5),
        MlmUtils::zhash_to_map (fty_proto_get_aux (msg)),
        MlmUtils::zhash_to_map (fty_proto_get_ext (msg))));
}

//  --------------------------------------------------------------------------
//  Self test of this class

// If your selftest reads SCMed fixture data, please keep it in
// src/selftest-ro; if your test creates filesystem objects, please
// do so under src/selftest-rw.
// The following pattern is suggested for C selftest code:
//    char *filename = NULL;
//    filename = zsys_sprintf ("%s/%s", SELFTEST_DIR_RO, "mytemplate.file");
//    assert (filename);
//    ... use the "filename" for I/O ...
//    zstr_free (&filename);
// This way the same "filename" variable can be reused for many subtests.
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

void
asset_test (bool verbose)
{
    printf (" * asset: ");

    //  @selftest
    //  Simple create/destroy test
    //  @end
    printf ("OK\n");
}
