import { isArray } from "@thi.ng/checks";
import { serializeGraph } from "@thi.ng/dot";
import { slugify } from "@thi.ng/strings";
import { isRef } from "./utils";
export const toDot = (graph, opts) => {
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
            // FIXME hash string
            const id = `lit-${slugify(String(val))}`;
            nodes[id] = { label: String(val).replace(/\n/g, "\\n") };
            edges.push({ src, dest: id, label: prop });
        }
    };
    Object.entries(graph).forEach(([id, node]) => {
        nodes[id] = { label: node.name || node.$id };
        Object.entries(node).forEach(([prop, val]) => {
            if (!filter(prop, node))
                return;
            isArray(val)
                ? val.forEach((v) => addEdge(id, prop, v))
                : addEdge(id, prop, val);
        });
    });
    return serializeGraph({
        attribs: opts.attribs,
        nodes,
        edges,
    });
};
