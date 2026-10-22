export class ApiError extends Error { constructor(public status:number, message:string){super(message)} }
export function rolloutTag(version:number){return `"rollout-${version}"`}
export function percentToBasisPoints(value:string){const n=Number(value);if(!Number.isFinite(n)||n<0||n>100)throw new Error('Percentage must be between 0 and 100');return Math.round(n*100)}
export async function request(path:string, token:string, workspace:string, method='GET', body?:unknown, extra:Record<string,string>={}) {
 const response=await fetch(path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`} : {}),'X-Rulease-Workspace':workspace,...extra},body:body===undefined?undefined:JSON.stringify(body)});
 const data=response.status===204?{}:await response.json();
 if(!response.ok)throw new ApiError(response.status,`${data.title??'Request failed'} (${response.status}) · ${data.request_id??''}`);
 return {data,etag:response.headers.get('ETag')??''};
}
