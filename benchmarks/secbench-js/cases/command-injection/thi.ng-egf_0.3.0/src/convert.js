import { isArray, isDate, isNumber, isPlainObject, isString, isTypedArray, } from "@thi.ng/checks";
import { base64Encode } from "@thi.ng/transducers-binary";
import { defPrefixer, isNode, isRef, isToEGF } from "./utils";
export const toEGF = (nodes, prefixes = {}, propFn) => {
    const prefixID = defPrefixer(prefixes);
    const res = [];
    for (let id in prefixes) {
        res.push(`@prefix ${id}: ${prefixes[id]}`);
    }
    res.push("");
    for (let node of nodes) {
        res.push(toEGFNode(node, prefixID, propFn), "");
    }
    return res.join("\n");
};
export const toEGFNode = (node, prefix, propFn = toEGFProp) => {
    if (isToEGF(node))
        return node.toEGF();
    const res = [prefix(node.$id) || node.$id];
    const $prop = (p, pid, v) => res.push(`\t${pid} ` +
        (isNode(v)
            ? `-> ${prefix(v.$id) || v.$id}`
            : isRef(v)
                ? `-> ${prefix(v.$ref) || v.$ref}`
                : isToEGF(v)
                    ? v.toEGF()
                    : propFn(p, v)));
    for (let p in node) {
        if (p === "$id")
            continue;
        const pid = prefix(p) || p;
        const val = node[p];
        if (isArray(val)) {
            for (let v of val) {
                $prop(p, pid, v);
            }
        }
        else {
            $prop(p, pid, val);
        }
    }
    return res.join("\n");
};
export const toEGFProp = (_, val) => isString(val)
    ? val.indexOf("\n") >= 0
        ? `>>>${val}<<<`
        : val
    : isNumber(val)
        ? `#num ${val}`
        : isDate(val)
            ? `#date ${val.toISOString()}`
            : isTypedArray(val)
                ? `#base64 ${base64Encode(new Uint8Array(val.buffer, val.byteOffset, val.byteLength))}`
                : isArray(val) || isPlainObject(val)
                    ? `#json ${JSON.stringify(val)}`
                    : String(val);
