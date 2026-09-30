import type { Fn2 } from "@thi.ng/api";
import { GraphAttribs } from "@thi.ng/dot";
import type { Node, Nodes } from "./api";
export interface GraphvizOpts {
    /**
     * Predicate function called for each property of each node. If the function
     * returns false, no edge will be created for that property.
     */
    filter: Fn2<string, Node, boolean>;
    attribs: Partial<GraphAttribs>;
}
export declare const toDot: (graph: Nodes, opts: Partial<GraphvizOpts>) => string;
//# sourceMappingURL=dot.d.ts.map