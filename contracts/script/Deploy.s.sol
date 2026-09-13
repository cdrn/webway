// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {WebwayRegistry} from "../src/WebwayRegistry.sol";

/// forge script script/Deploy.s.sol --rpc-url $RPC --private-key $KEY --broadcast
contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        WebwayRegistry r = new WebwayRegistry();
        vm.stopBroadcast();
        console.log("WebwayRegistry deployed at", address(r));
    }
}
