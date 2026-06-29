export declare const CREATEX: "0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed";
export declare const CREATEX_ABI: readonly [{
    readonly type: "function";
    readonly name: "deployCreate3";
    readonly inputs: readonly [{
        readonly name: "salt";
        readonly type: "bytes32";
    }, {
        readonly name: "initCode";
        readonly type: "bytes";
    }];
    readonly outputs: readonly [{
        readonly name: "newContract";
        readonly type: "address";
    }];
    readonly stateMutability: "payable";
}, {
    readonly type: "function";
    readonly name: "computeCreate3Address";
    readonly inputs: readonly [{
        readonly name: "salt";
        readonly type: "bytes32";
    }, {
        readonly name: "deployer";
        readonly type: "address";
    }];
    readonly outputs: readonly [{
        readonly name: "computedAddress";
        readonly type: "address";
    }];
    readonly stateMutability: "view";
}];
