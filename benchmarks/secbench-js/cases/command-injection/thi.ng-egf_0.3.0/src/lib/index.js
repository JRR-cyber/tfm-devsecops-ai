'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var checks = require('@thi.ng/checks');
var errors = require('@thi.ng/errors');
var transducersBinary = require('@thi.ng/transducers-binary');
var associative = require('@thi.ng/associative');
var dot = require('@thi.ng/dot');
var strings = require('@thi.ng/strings');
var api = require('@thi.ng/api');
var $prefixes = require('@thi.ng/prefixes');
var fs = require('fs');
var path = require('path');
var child_process = require('child_process');

const IS_NODE = checks.isNode();
const NODE_ONLY = () => errors.unsupported("only available in NodeJS");

const isNode = (x) => checks.isPlainObject(x) && "$id" in x;
const isRef = (x) => checks.isPlainObject(x) && "$ref" in x;
const isToEGF = (x) => checks.implementsFunction(x, "toEGF");
const RE_QFN = /^([a-z0-9-_$]*):([a-z0-9-_$.+]+)$/i;
const qualifiedID = (prefixes, id) => {
    if (id[0] === "<" && id[id.length - 1] === ">") {
        return id.substring(1, id.length - 1);
    }
    if (id.indexOf(":") !== -1) {
        const match = RE_QFN.exec(id);
        if (match) {
            const prefix = prefixes[match[1]];
            return prefix
                ? prefix + match[2]
                : errors.illegalArgs(`unknown prefix: ${id}`);
        }
    }
    return id;
};
const defPrefixer = (prefixes) => {
    const uriToID = new associative.TrieMap();
    Object.entries(prefixes).forEach(([id, url]) => uriToID.set(url, id));
    return (uri) => {
        const known = uriToID.knownPrefix(uri);
        return known
            ? uriToID.get(known) + ":" + uri.substr(known.length)
            : undefined;
    };
};
const defVocab = (uri) => (name = "") => uri + name;

const toEGF = (nodes, prefixes = {}, propFn) => {
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
const toEGFNode = (node, prefix, propFn = toEGFProp) => {
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
        if (checks.isArray(val)) {
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
const toEGFProp = (_, val) => checks.isString(val)
    ? val.indexOf("\n") >= 0
        ? `>>>${val}<<<`
        : val
    : checks.isNumber(val)
        ? `#num ${val}`
        : checks.isDate(val)
            ? `#date ${val.toISOString()}`
            : checks.isTypedArray(val)
                ? `#base64 ${transducersBinary.base64Encode(new Uint8Array(val.buffer, val.byteOffset, val.byteLength))}`
                : checks.isArray(val) || checks.isPlainObject(val)
                    ? `#json ${JSON.stringify(val)}`
                    : String(val);

const toDot = (graph, opts) => {
    const nodes = {};
    const edges = [];
    const filter = opts.filter || (() => true);
    const addEdge = (src, prop, val) => {
        if (isRef(val)) {
            edges.push({ src, dest: val.$ref, label: prop });
        }
        else if (val.$id) {
            edges.push({ src, dest: val.$id, label: prop });
        }
        else {
            const id = `lit-${strings.slugify(String(val))}`;
            nodes[id] = { label: String(val).replace(/\n/g, "\\n") };
            edges.push({ src, dest: id, label: prop });
        }
    };
    Object.entries(graph).forEach(([id, node]) => {
        nodes[id] = { label: node.name || node.$id };
        Object.entries(node).forEach(([prop, val]) => {
            if (!filter(prop, node))
                return;
            checks.isArray(val)
                ? val.forEach((v) => addEdge(id, prop, v))
                : addEdge(id, prop, val);
        });
    });
    return dot.serializeGraph({
        attribs: opts.attribs,
        nodes,
        edges,
    });
};

const BUILTINS = {
    base64: IS_NODE
        ? (_, body) => Buffer.from(body, "base64")
        : (_, body) => new Uint8Array([...transducersBinary.base64Decode(body)]),
    date: (_, body) => new Date(body),
    file: (_, path$1, ctx) => {
        if (IS_NODE && ctx.opts.includes) {
            path$1 = path.resolve(ctx.opts.root, strings.unescape(path$1));
            ctx.logger.debug("loading value from:", path$1);
            return fs.readFileSync(path$1).toString();
        }
        else {
            ctx.logger.debug("skipping file value:", path$1);
            return path$1;
        }
    },
    gpg: IS_NODE
        ? (_, body, ctx) => (ctx.opts.decrypt
            ? child_process.execSync(`echo "${body}" | gpg --decrypt`).toString()
            : body).trim()
        : NODE_ONLY,
    hex: (_, body) => strings.maybeParseInt(body, 0, 16),
    json: (_, body) => JSON.parse(strings.unescape(body)),
    list: (_, body) => body.split(/[\n\r\t ]+/g).map(strings.unescape),
    num: (_, body) => strings.maybeParseFloat(body, 0),
};

const INCLUDE = "@include ";
const PREFIX = "@prefix ";
const parse = (src, ctx) => {
    const lines = src.split(/\r?\n/);
    const nodes = ctx.nodes;
    const usePrefixes = ctx.opts.prefixes;
    for (let i = 0, n = lines.length; i < n;) {
        let subj = lines[i++];
        if (!subj.length || subj[0] === ";")
            continue;
        if (subj[0] === "@") {
            if (subj.startsWith(INCLUDE)) {
                parseInclude(subj, ctx);
                continue;
            }
            else if (subj.startsWith(PREFIX)) {
                usePrefixes && parsePrefix(subj, ctx);
                continue;
            }
        }
        subj = strings.unescape(subj);
        usePrefixes && (subj = qualifiedID(ctx.prefixes, subj));
        const curr = nodes[subj] || (nodes[subj] = { $id: subj });
        while (i < n) {
            let line = lines[i];
            if (line[0] === "\t" || line.startsWith("    ")) {
                i = parseProp(curr, ctx, line, lines, i);
            }
            else if (!line.length) {
                i++;
                break;
            }
            else if (line[0] === ";") {
                i++;
            }
            else
                errors.illegalState(`expected property or comment @ line: ${i}`);
        }
    }
    ctx.opts.resolve && ctx.opts.prune && pruneNodes(ctx);
    return ctx;
};
const parseInclude = (line, ctx) => {
    const path$1 = strings.unescape(line.substr(INCLUDE.length));
    if (IS_NODE && ctx.opts.includes) {
        $parseFile(path$1, Object.assign(Object.assign({}, ctx), { cwd: path.dirname(ctx.file), prefixes: Object.assign({}, ctx.prefixes), opts: Object.assign(Object.assign({}, ctx.opts), { prune: false }) }));
    }
    else {
        ctx.logger.debug("skipping include:", path$1);
    }
};
const RE_PREFIX = /^([a-z0-9-_$]*)$/i;
const parsePrefix = (line, ctx) => {
    const idx = line.indexOf(": ", PREFIX.length);
    if (idx > 0) {
        const id = strings.unescape(line.substring(PREFIX.length, idx));
        if (RE_PREFIX.test(id)) {
            const val = strings.unescape(line.substr(idx + 2).trim());
            if (val.length) {
                ctx.logger.debug(`declare prefix: ${id} = ${val}`);
                ctx.prefixes[id] = val;
                return;
            }
        }
    }
    errors.illegalState(`invalid prefix decl: ${line}`);
};
const parseTag = (tag, body, ctx) => {
    const parser = ctx.tags[tag] || ctx.defaultTag;
    return parser
        ? parser(tag, body, ctx)
        : errors.unsupported(`missing parser for tag: ${tag}`);
};
const parseProp = (node, ctx, line, lines, i) => {
    const idx0 = line[0] === "\t" ? 1 : 4;
    if (line[idx0] === ";")
        return ++i;
    let idx = line.indexOf(" ", idx0);
    let key = strings.unescape(line.substring(idx0, idx));
    ctx.opts.prefixes && (key = qualifiedID(ctx.prefixes, key));
    let tag;
    let body;
    idx++;
    if (line[idx] === "-" && line[idx + 1] === ">") {
        addProp(ctx.index, node, key, parseRef(strings.unescape(line.substr(idx + 2).trim()), ctx));
        return ++i;
    }
    else if (line[idx] === "#") {
        const tstart = idx + 1;
        idx = line.indexOf(" ", tstart);
        tag = strings.unescape(line.substring(tstart, idx));
        idx++;
    }
    if (line[idx] === ">" && line[idx + 1] === ">" && line[idx + 2] === ">") {
        body = line.substr(idx + 3);
        idx = body.indexOf("<<<");
        if (idx < 0) {
            const n = lines.length;
            let closed = false;
            while (++i < n) {
                line = lines[i];
                idx = line.indexOf("<<<");
                if (idx >= 0) {
                    body += "\n" + line.substr(0, idx);
                    closed = true;
                    i++;
                    break;
                }
                else {
                    body += "\n" + line;
                }
            }
            !closed && errors.illegalState("unterminated value, EOF reached");
        }
        else {
            body = body.substr(0, idx);
            i++;
        }
    }
    else {
        body = line.substr(idx);
        i++;
    }
    body = body.trim();
    addProp(ctx.index, node, key, tag ? parseTag(tag, body, ctx) : strings.unescape(body));
    return i;
};
const addProp = (index, acc, key, val) => {
    const exist = acc[key];
    const id = acc.$id + "~" + key;
    if (exist !== undefined) {
        ++index[id] > 2 ? exist.push(val) : (acc[key] = [exist, val]);
    }
    else {
        acc[key] = val;
        index[id] = 1;
    }
};
const parseRef = (id, ctx) => {
    ctx.opts.prefixes && (id = qualifiedID(ctx.prefixes, id));
    return ctx.opts.resolve
        ? ctx.nodes[id] || (ctx.nodes[id] = { $id: id })
        : {
            $ref: id,
            deref() {
                return ctx.nodes[id];
            },
            equiv(o) {
                return o != null && o.$ref === this.$ref;
            },
        };
};
const pruneNodes = ({ nodes, logger }) => {
    for (let id in nodes) {
        const keys = Object.keys(nodes[id]);
        if (keys.length === 1 && keys[0] === "$id") {
            logger.debug("pruning node:", id);
            delete nodes[id];
        }
    }
};
const initContext = (ctx = {}) => {
    const opts = Object.assign({ decrypt: false, includes: true, prefixes: false, prune: false, resolve: false }, ctx.opts);
    return {
        cwd: ctx.cwd || ".",
        file: ctx.file || "",
        files: ctx.files || [],
        nodes: ctx.nodes || {},
        index: ctx.index || {},
        tags: Object.assign(Object.assign({}, BUILTINS), ctx.tags),
        defaultTag: ctx.defaultTag,
        prefixes: ctx.prefixes
            ? Object.assign({}, ctx.prefixes) : Object.assign(Object.assign({}, $prefixes), { void: $prefixes.VOID }),
        logger: ctx.logger || api.NULL_LOGGER,
        opts,
    };
};
const $parseFile = (path$1, ctx) => {
    const $ctx = initContext(ctx);
    $ctx.file = path$1 = path.resolve($ctx.cwd, path$1);
    if ($ctx.files.includes(path$1)) {
        $ctx.logger.warn("file already processed, skipping:", path$1);
        return $ctx;
    }
    $ctx.files.push(path$1);
    $ctx.logger.debug("loading file:", path$1);
    return parse(fs.readFileSync(path$1).toString(), $ctx);
};
const parseFile = (path, ctx) => {
    const res = $parseFile(path, ctx);
    return { nodes: res.nodes, prefixes: res.prefixes };
};
const parseString = (src, ctx) => {
    const res = parse(src, initContext(ctx));
    return { nodes: res.nodes, prefixes: res.prefixes };
};

exports.$parseFile = $parseFile;
exports.BUILTINS = BUILTINS;
exports.IS_NODE = IS_NODE;
exports.NODE_ONLY = NODE_ONLY;
exports.defPrefixer = defPrefixer;
exports.defVocab = defVocab;
exports.isNode = isNode;
exports.isRef = isRef;
exports.isToEGF = isToEGF;
exports.parse = parse;
exports.parseFile = parseFile;
exports.parseString = parseString;
exports.qualifiedID = qualifiedID;
exports.toDot = toDot;
exports.toEGF = toEGF;
exports.toEGFNode = toEGFNode;
exports.toEGFProp = toEGFProp;
