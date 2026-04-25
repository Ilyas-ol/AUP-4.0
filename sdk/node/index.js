const ffi = require('ffi-napi');
const ref = require('ref-napi');

const LIB_PATH = process.env.AUP_SDK_LIB || './aup_sdk.dll';

const lib = ffi.Library(LIB_PATH, {
    sdk_verify_license_json: ['int', ['string', 'string', 'string', 'uint', 'string', 'string']],
    sdk_last_error: ['size_t', ['pointer', 'size_t']]
});

function lastError() {
    const size = lib.sdk_last_error(ref.NULL, 0);
    if (size === 0) {
        return '';
    }
    const buf = Buffer.alloc(size);
    lib.sdk_last_error(buf, buf.length);
    return buf.toString('utf8').replace(/\0+$/, '');
}

function verifyLicenseJson(options) {
    const result = lib.sdk_verify_license_json(
        options.licenseJson,
        options.publicKeyB64,
        options.today,
        options.requestedUsers || 0,
        options.requestedModulesCsv || '',
        options.machineBinding || ''
    );

    return {
        code: result,
        error: result === 0 ? '' : lastError()
    };
}

module.exports = {
    verifyLicenseJson
};
