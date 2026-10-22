import {test,expect} from '@playwright/test';
test('login, editor preview, queued replay and rollout preconditions',async({page})=>{
 const calls:{path:string,method:string,headers:Record<string,string>,body:any}[]=[];
 await page.route('**/v2/**',async route=>{
  const req=route.request(),path=new URL(req.url()).pathname,method=req.method();let body:any={};try{body=req.postDataJSON()}catch{}
  calls.push({path,method,headers:req.headers(),body});let result:any={items:[]},headers={'Content-Type':'application/json'};
  if(path==='/v2/auth/login')result={session_token:'session-token'};
  else if(path==='/v2/projects')result={items:[{key:'commerce',name:'Commerce'}],permissions:['policy:read','policy:write','revision:create','deployment:create','deployment:approve','deployment:release','decision:read']};
  else if(path.endsWith('/policies'))result={items:[{key:'checkout',name:'Checkout'}]};
  else if(path.endsWith('/draft')){result={source:'rule discount:\n    when: amount >= 10000\n    reason: minimum_total\n',context_schema:{}};headers={...headers,'ETag':'"draft-1"'} as any}
  else if(path==='/v2/preview')result={result:'DENY',reason:'minimum_total'};
  else if(path.endsWith('/simulations'))result={simulation_id:'sim-1',status:'queued'};
  else if(path.endsWith('/environments'))result={items:[{key:'production',version:2}]};
  else if(path.endsWith('/deployments'))result={items:[{deployment_id:'dep-1',environment:'production',status:'released'}]};
  else if(path.endsWith('/rollout'))result={deployment_id:'dep-1',mode:'canary',state:'active',basis_points:500,version:3};
  await route.fulfill({json:result,headers});
 });
 await page.goto('/admin/');
 await page.getByLabel('Username',{exact:true}).fill('owner');await page.getByLabel('Password',{exact:true}).fill('password');await page.getByRole('button',{name:'ログイン',exact:true}).click();
 await page.getByRole('button',{name:'ポリシー',exact:true}).first().click();
 await page.getByRole('button',{name:'Checkout checkout'}).click();
 await page.getByRole('button',{name:'プレビュー',exact:true}).click();await expect(page.locator('pre').last()).toContainText('DENY');
 expect(calls.find(c=>c.path==='/v2/preview')?.headers['x-rulease-workspace']).toBe('team');
 await page.getByRole('button',{name:'再生・比較',exact:true}).click();await page.getByLabel('Policy key').fill('checkout');await page.getByRole('button',{name:'Queue replay'}).click();await expect(page.getByLabel('Simulation ID')).toHaveValue('sim-1');
 expect(calls.find(c=>c.path.endsWith('/simulations'))?.headers['idempotency-key']).toBeTruthy();
 await page.getByRole('button',{name:'デプロイ',exact:true}).click();await page.getByRole('button',{name:'production · released dep-1'}).click();await page.getByRole('button',{name:'Inspect rollout'}).click();await page.getByRole('button',{name:'pause',exact:true}).click();
 expect(calls.find(c=>c.method==='PATCH')?.headers['if-match']).toBe('"rollout-3"');
 await page.screenshot({path:'test-results/console-desktop.png',fullPage:true});
 await page.setViewportSize({width:390,height:844});await page.screenshot({path:'test-results/console-mobile.png',fullPage:true});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 expect(await page.evaluate(()=>localStorage.length)).toBe(0);
});
