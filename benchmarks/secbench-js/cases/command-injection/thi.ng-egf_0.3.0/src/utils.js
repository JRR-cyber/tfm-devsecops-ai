import { TrieMap } from "@thi.ng/associative";
import { implementsFunction, isPlainObject } from "@thi.ng/checks";
import { illegalArgs } from "@thi.ng/errors";
export const isNode = (x) => isPlainObject(x) && "$id" in x;
export const isRef = (x) => isPlainObject(x) && "$ref" in x;
export const isToEGF = (x) => implementsFunction(x, "toEGF");
const RE_QFN = /^([a-z0-9-_$]*):([a-z0-9-_$.+]+)$/i;
export const qualifiedID = (prefixes, id) => {
    if (id[0] === "<" && id[id.length - 1] === ">") {
        return id.substring(1, id.length - 1);
    }
    if (id.indexOf(":") !== -1) {
        const match = RE_QFN.exec(id);
        if (match) {
            const prefix = prefixes[match[1]];
            return prefix
                ? prefix + match[2]
                : illegalArgs(`unknown prefix: ${id}`);
        }
    }
    return id;
};
export const defPrefixer = (prefixes) => {
    const uriToID = new TrieMap();
    Object.entries(prefixes).forEach(([id, url]) => uriToID.set(url, id));
    return (uri) => {
        const known = uriToID.knownPrefix(uri);
        return known
            ? uriToID.get(known) + ":" + uri.substr(known.length)
            : undefined;
    };
};
export const defVocab = (uri) => (name = "") => uri + name;
