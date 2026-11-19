'use strict';
// T2 driver — code-injection/pixl-class_1.0.0. Sink: class.js (eval of the parent
// constructor's source to build the child constructor). Observation: the behaviour
// of classes built by create() — constructor effects, inherited and own methods,
// statics, mixins and the EventEmitter default — never the generated source.
const { EventEmitter } = require('events');

function Parent(a, b) { this.sum = a + b; this.kind = 'parent'; }
Parent.prototype.describe = function describe() { return `${this.kind}:${this.sum}`; };

function NoArgs() { this.ready = true; }

function Mixin() {}
Mixin.prototype.greet = function greet() { return `hello ${this.name}`; };
Mixin.__static = { VERSION: '1.0' };

const scenarios = {
  'base-class': (create) => {
    const C = create({ __construct: function C(n) { this.name = n; }, label() { return `[${this.name}]`; } });
    const c = new C('box');
    return { name: c.name, label: c.label(), emitter: c instanceof EventEmitter };
  },
  'inherit-parent-constructor': (create) => {
    const C = create({ __parent: Parent, twice() { return this.sum * 2; } });
    const c = new C(2, 3);
    return { sum: c.sum, kind: c.kind, describe: c.describe(), twice: c.twice(), isParent: c instanceof Parent };
  },
  'inherit-no-args': (create) => {
    const C = create({ __parent: NoArgs, state() { return this.ready ? 'ready' : 'idle'; } });
    const c = new C();
    return { ready: c.ready, state: c.state(), isParent: c instanceof NoArgs };
  },
  'explicit-construct': (create) => {
    const C = create({ __parent: Parent, __construct: function C(x) { Parent.call(this, x, 10); this.kind = 'child'; } });
    const c = new C(5);
    return { sum: c.sum, describe: c.describe() };
  },
  'static-members': (create) => {
    const C = create({ __static: { MAX: 10, make() { return 'made'; } } });
    return { max: C.MAX, make: C.make() };
  },
  'events-disabled': (create) => {
    const C = create({ __events: false, value: 7 });
    const c = new C();
    return { value: c.value, hasOn: typeof c.on };
  },
  mixin: (create) => {
    const C = create({ __construct: function C() { this.name = 'mix'; }, __mixins: [Mixin] });
    const c = new C();
    return { greet: c.greet(), version: C.VERSION, emitter: typeof c.emit };
  },
};

module.exports = {
  stubChildProcess: false,
  compareCalls: false,
  inputs: Object.keys(scenarios),
  run: (cls, scenario) => scenarios[scenario](cls.create),
};
