import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { pinnedEngineMetadata } from "./native-fixture-hooks-135.mjs";

const review=JSON.parse(readFileSync(new URL("./native-fixture-review-135.json",import.meta.url),"utf8"));
const carrier=review.engineCarriers.windows;
const canonical={id:carrier.engineReleaseId,tag_name:"v0.4.127",target_commitish:carrier.engineSourceCommit,prerelease:false,
    assets:[{id:carrier.engineAssetId,name:carrier.name.replace("qa-only-native135-engine-","happy-agent-"),size:carrier.size,digest:"sha256:"+carrier.sha256}]};
const draft={id:carrier.releaseId,tag_name:"v0.0.135",draft:true,prerelease:true,body:"https://github.com/CyberfiTechh/CyberFi/commit/"+review.sourceCommit,
    assets:[{id:carrier.assetId,name:carrier.name,size:carrier.size,digest:"sha256:"+carrier.sha256}]};
function mocked(status, original=canonical, own=draft){
    const calls=[];return{calls,fetcher:async(url,options)=>{calls.push(url);assert.equal(options.redirect,"error");
        if(url.includes("/CyberFi-Engine/")){assert.equal(options.headers.Authorization,undefined);return{status,json:async()=>original};}
        assert(url===`https://api.github.com/repos/CyberfiTechh/CyberFi-Releases/releases/${carrier.releaseId}`);
        assert.equal(options.headers.Authorization,"Bearer synthetic-test-token");return{status:200,json:async()=>own};}};
}
let m=mocked(200);let result=await pinnedEngineMetadata(carrier,"synthetic-test-token",m.fetcher);
assert.equal(result.repository,carrier.engineRepository);assert.equal(result.asset.id,carrier.engineAssetId);assert.equal(m.calls.length,1);
for(const status of[403,404]){m=mocked(status);result=await pinnedEngineMetadata(carrier,"synthetic-test-token",m.fetcher);assert.equal(result.asset.id,carrier.assetId);assert.equal(result.provenance.originalMetadataHttpStatus,status);assert.equal(m.calls.length,2);}
for(const status of[401,429,500]){m=mocked(status);await assert.rejects(()=>pinnedEngineMetadata(carrier,"synthetic-test-token",m.fetcher));assert.equal(m.calls.length,1);}
m=mocked(200,{...canonical,target_commitish:"0".repeat(40)});await assert.rejects(()=>pinnedEngineMetadata(carrier,"synthetic-test-token",m.fetcher));assert.equal(m.calls.length,1);
m=mocked(200,{...canonical,assets:[{...canonical.assets[0],digest:"sha256:"+"0".repeat(64)}]});await assert.rejects(()=>pinnedEngineMetadata(carrier,"synthetic-test-token",m.fetcher));assert.equal(m.calls.length,1);
m=mocked(404,canonical,{...draft,draft:false});await assert.rejects(()=>pinnedEngineMetadata(carrier,"synthetic-test-token",m.fetcher));
console.log("Pinned canonical engine/fallback403404/other-status refusal/hash-source guards PASS; no network or process launched.");
