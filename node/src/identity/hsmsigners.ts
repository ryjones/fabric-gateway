/*
 * Copyright 2021 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import * as pkcs11js from 'pkcs11js';
import * as elliptic from 'elliptic';
import BN = require("bn.js");
const ecSignature = require('elliptic/lib/elliptic/ec/signature.js');  // eslint-disable-line
import { Signer } from './signer';

type DER = string | number[];

export interface HSMSignerOptions {
    /**
     * the path to the PKCS11 library
     */
    library: string;

    /**
     * The label associated with the token for the slot
     */
    label: string;

    /**
     * The pin for the slot identified by the label
     */
    pin: string;

    /**
     * Identifier. The CKA_ID assigned to the HSM object
     */
    identifier: string | Buffer;

    /**
     * Optional user type for the HSM. If not specified it defaults to CKU_USER
     */
    userType?: number;
}

export type HSMClose = () => void;
export type HSMSigner = {signer: Signer, close: HSMClose};

let hsmSignerFactory: HSMSignerFactory | undefined;

/**
 * Create a new HSM signing implementation based on provided HSM options.
 *
 * This returns an object with 2 properties
 * - signer which is the signer function
 * - close which is a close function to close the signer when it's not required anymore
 *
 * @param hsmSignerOptions - The HSM signer options
 * @returns an HSM Signer implementation
 */
export const newHSMSigner = (hsmSignerOptions: HSMSignerOptions): HSMSigner => {
    if (!hsmSignerFactory) {

        if (!hsmSignerOptions.library || hsmSignerOptions.library.trim() === '') {
            throw new Error('library property must be provided');
        }

        hsmSignerFactory = new HSMSignerFactory(hsmSignerOptions.library);
    }

    if (!hsmSignerOptions.label || hsmSignerOptions.label.trim() === '') {
        throw new Error('label property must be provided');
    }

    if (!hsmSignerOptions.pin || hsmSignerOptions.pin.trim() === '') {
        throw new Error('pin property must be provided');
    }

    if (!hsmSignerOptions.identifier || hsmSignerOptions.identifier.toString().trim() === '') {
        throw new Error('identifier property must be provided');
    }

    const supportedKeySize = 256;

    return hsmSignerFactory.newSigner(hsmSignerOptions.label, hsmSignerOptions.pin, hsmSignerOptions.userType, supportedKeySize, hsmSignerOptions.identifier);
}

class HSMSignerFactory {

    #pkcs11: pkcs11js.PKCS11;

    constructor(library: string) {
        this.#pkcs11 = new pkcs11js.PKCS11()
        this.#pkcs11.load(library);
        this.#pkcs11.C_Initialize();
    }

    public newSigner(label: string, pin: string, userType: number = pkcs11js.CKU_USER, keySize: number, identifier: string | Buffer): {signer: Signer, close: () => void} {
        const pkcs11 = this.#pkcs11;
        const slot = this.findSlotForLabel(label);
        const session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION);
        pkcs11.C_Login(session, userType, pin);
        const privateKeyHandle = this.findObjectInHSM(session, pkcs11js.CKO_PRIVATE_KEY, identifier);

        const curveName = `secp${keySize}r1`;
        const definedCurves = elliptic.curves as unknown as { [key: string]: elliptic.curves.PresetCurve };
        const ecdsaCurve = definedCurves[`p${keySize}`];

        const close = () => {
            pkcs11.C_Logout(session);
            pkcs11.C_CloseSession(session);
        }

        const signer: Signer = async (digest: Uint8Array) => {
            pkcs11.C_SignInit(session, { mechanism: pkcs11js.CKM_ECDSA }, privateKeyHandle);
            const sig = pkcs11.C_Sign(session, Buffer.from(digest), Buffer.alloc(keySize));

            const r = new BN(sig.slice(0, sig.length / 2).toString('hex'), 16);
            let s = new BN(sig.slice(sig.length / 2).toString('hex'), 16);
            const halfOrder = ecdsaCurve.n?.shrn(1);

            if (!halfOrder) {
                throw new Error(`Can not find the half order needed to calculate "s" value for immalleable signatures. Unsupported curve name ${curveName}`);
            }

            if (s.cmp(halfOrder) === 1) {
                const bigNum = ecdsaCurve.n;
                if (!bigNum) {
                    throw new Error(`Unexpected problem for ${curveName}, no 'n' provided`);
                }
                s = bigNum.sub(s);
            }

            const signatureInput: elliptic.SignatureInput = {
                r,
                s
            }

            const der = new ecSignature(signatureInput).toDER() as DER; // eslint-disable-line
            return Promise.resolve(Buffer.from(der));
        }

        return {signer, close};
    }

    private findSlotForLabel(pkcs11Label: string): Buffer {
        const slots = this.#pkcs11.C_GetSlotList(true);

        if (!slots || slots.length === 0) {
            throw new Error('No pkcs11 slots can be found');
        }

        let slot: Buffer | undefined;
        let tokenInfo: pkcs11js.TokenInfo;

        for (const slotToCheck of slots) {
            tokenInfo = this.#pkcs11.C_GetTokenInfo(slotToCheck);
            if (tokenInfo && tokenInfo.label && tokenInfo.label.trim() === pkcs11Label) {
                slot = slotToCheck;
                break;
            }
        }

        if (!slot) {
            throw new Error(`label ${pkcs11Label} cannot be found in the pkcs11 slot list`);
        }

        return slot;
    }

    private findObjectInHSM(session: Buffer, keytype: number, identifier: string | Buffer): Buffer {
        const pkcs11Template: pkcs11js.Template = [
            { type: pkcs11js.CKA_ID, value: identifier },
            { type: pkcs11js.CKA_CLASS, value: keytype },
            { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_EC }
        ]
        this.#pkcs11.C_FindObjectsInit(session, pkcs11Template);

        const hsmObjects = this.#pkcs11.C_FindObjects(session, 1);

        if (!hsmObjects || hsmObjects.length === 0) {
            this.#pkcs11.C_FindObjectsFinal(session);
            throw new Error(`Unable to find object in HSM with ID ${identifier.toString()}`);
        }

        this.#pkcs11.C_FindObjectsFinal(session);

        return hsmObjects[0];
    }
}
