'use strict';
// Pure settings checks: no Level database, server or plugin is opened.
const assert = require('node:assert/strict');
const { collect, verify } = require('../scrypted-datastore.js');
const safe = [
  {global_decoder:true, field:'hwaccel', value:'none'},
  {global_decoder:true, field:'hwscalar', value:'Software'},
  {global_decoder:false, field:'hwaccel', value:'Default'},
  {global_decoder:false, field:'hwscalar', value:'Default'},
  {global_decoder:false, field:'openclMotion', value:false},
];
assert.doesNotThrow(() => verify(1, safe));
for (const count of [0, 2]) assert.throws(() => verify(count, safe));
for (const field of ['hwaccel', 'hwscalar'])
  assert.throws(() => verify(1, safe.filter(x => !(x.global_decoder && x.field === field))));
for (const [field, values] of [
  ['hwaccel', ['vaapi', 'cuda', 'vulkan', 'qsv', 'AUTO', 'unrecognised', true]],
  ['hwscalar', ['Hardware', 'AUTO', 'unrecognised', true]],
  ['openclMotion', [true, 'unrecognised', 'Default']],
]) for (const value of values)
  assert.throws(() => verify(1, [...safe, {global_decoder:false, field, value}]));
for (const value of ['Default', null, 'unrecognised'])
  assert.throws(() => verify(1, safe.map(x => x.global_decoder && x.field === 'hwaccel'
    ? {...x, value} : x)));
const source = {
  password:'PRIVATE_SENTINEL',
  settings:JSON.stringify({hwaccel:'none', camera:JSON.stringify({hwscalar:'Software'})}),
  children:[{openclMotion:'false'}, {hwaccel:'PRIVATE_SENTINEL'}],
};
const before = JSON.stringify(source), observed = [];
collect(source, [], observed);
assert.equal(JSON.stringify(source), before);
assert.deepEqual(observed.map(x => x.value), ['none', 'Software', false, 'unrecognised']);
assert.equal(JSON.stringify(observed).includes('PRIVATE_SENTINEL'), false);
for (const value of ['null', '"none"', '"Default"']) {
  const selected=[];
  collect({hwaccel:value}, [], selected);
  assert.equal(selected[0].value, 'unrecognised');
  assert.throws(() => verify(1, [...safe, {
    global_decoder:false, field:'hwaccel', value:selected[0].value}]));
}
assert.throws(() => collect({list:Array(1001).fill(null)}, [], []), /array_bound/);
assert.throws(() => collect({hwaccel:'none'}, [], Array(10000).fill({})), /observation_bound/);
let nested = {hwaccel:'none'};
for (let i=0; i<14; i++) nested = {nested};
assert.throws(() => collect(nested, [], []), /nested_data_bound/);
console.log('Scrypted software decoder settings checks passed');
