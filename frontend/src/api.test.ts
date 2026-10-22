import {describe,it,expect,vi,afterEach} from 'vitest';
import {request,ApiError,percentToBasisPoints,rolloutTag} from './api';
afterEach(()=>vi.unstubAllGlobals());
describe('control plane requests',()=>{
 it('keeps tenant and precondition on mutations',async()=>{const fetch=vi.fn().mockResolvedValue(new Response('{}',{headers:{ETag:'"rollout-3"'}}));vi.stubGlobal('fetch',fetch);const r=await request('/v2/rollout','token','team','PATCH',{action:'pause'},{'If-Match':rolloutTag(2)});expect(fetch.mock.calls[0][1].headers).toMatchObject({'X-Rulease-Workspace':'team',Authorization:'Bearer token','If-Match':'"rollout-2"'});expect(r.etag).toBe('"rollout-3"')});
 it('surfaces auth failure instead of returning success',async()=>{vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response('{"title":"Expired","request_id":"abc"}',{status:401})));await expect(request('/v2/jobs','bad','team')).rejects.toBeInstanceOf(ApiError)});
 it('supports no-content operations',async()=>{vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response(null,{status:204})));expect((await request('/logout','t','w','POST')).data).toEqual({})});
 it('rejects invalid percentages',()=>{expect(percentToBasisPoints('0.5')).toBe(50);for(const v of ['NaN','-1','101'])expect(()=>percentToBasisPoints(v)).toThrow()});
});
