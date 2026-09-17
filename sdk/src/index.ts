import type { Operations, Schemas } from './generated.js';
export type { Operations, Schemas } from './generated.js';
export type ConfigurationKind = Schemas['privacy-proxy_internal_configuration.Kind'];
export type ConfigurationRevision = Schemas['privacy-proxy_internal_apimodels.ConfigurationRevision'];
export type ConfigurationReview = Schemas['privacy-proxy_internal_apimodels.ConfigurationReview'];
export type ConfigurationContext = Schemas['privacy-proxy_internal_apimodels.ConfigurationContext'];
export type CIApproval = Schemas['privacy-proxy_internal_configuration.CIApproval'];
export type NodeSimulation = Schemas['privacy-proxy_internal_apimodels.NodeSimulationRequest'];
export type TransactionProgress = Schemas['privacy-proxy_internal_apimodels.NodeTransactionProgress'];
export interface Session { accessToken: string; refreshToken?: string }
export interface ClientOptions { baseUrl: string; session?: Session; fetch?: typeof globalThis.fetch }
export interface ReviewedConfiguration {
  readonly orgId: string;
  readonly kind: ConfigurationKind;
  readonly revisionId: string;
  readonly coactivate: readonly string[];
  readonly review: ConfigurationReview;
  readonly candidateDigests: Readonly<Record<string,string>>;
}
type RequestInput<O extends keyof Operations> = Omit<Operations[O], 'response'> & {signal?: AbortSignal};

export class OpsError extends Error {
  constructor(public readonly status: number, public readonly response: unknown) {
    super(`OPS request failed (${status})`); this.name='OpsError';
  }
}
export class RpcError extends Error {
  constructor(public readonly code: number, message: string, public readonly data?: unknown) {
    super(message); this.name='RpcError';
  }
}

// Sessions remain in memory. No operator token, environment lookup, token log,
// transparent mutation retry, cookie session or activation side effect.
export class OpsClient {
  readonly #base: URL;
  readonly #fetch: typeof globalThis.fetch;
  #session?: Session;
  #refresh?: {epoch:number;promise:Promise<Session>};
  #sessionEpoch=0;
  #rpcId=0;
  constructor(options: ClientOptions) {
    const base=new URL(options.baseUrl);
    if(!['http:','https:'].includes(base.protocol)||base.username||base.password||base.search||base.hash||!['','/'].includes(base.pathname)) throw Error('OPS base URL must be an HTTP(S) origin without credentials');
    this.#base=base; this.#fetch=options.fetch??globalThis.fetch;
    this.#session=options.session?{...options.session}:undefined;
  }
  get session(): Session|undefined {return this.#session?{...this.#session}:undefined;}
  setSession(session:Session|undefined):void {this.#sessionEpoch++;this.#session=session?{...session}:undefined;}

  async #send<T>(method:string,path:string,body?:unknown,options:{raw?:boolean;anonymous?:boolean;signal?:AbortSignal;headers?:Record<string,string>}={}):Promise<T> {
    const url=new URL(path,this.#base);
    if(url.origin!==this.#base.origin)throw Error('OPS request must remain on its configured origin');
    const headers=new Headers(options.headers);
    headers.set('Accept','application/json');
    // Callers cannot override the named principal through generated headers.
    headers.delete('Authorization'); headers.delete('X-Admin-Token'); headers.delete('X-Operator-Token');
    if(!options.anonymous&&this.#session)headers.set('Authorization',`Bearer ${this.#session.accessToken}`);
    if(body!==undefined)headers.set('Content-Type','application/json');
    const response=await this.#fetch(url,{method,headers,body:body===undefined?undefined:options.raw?String(body):JSON.stringify(body),redirect:'error',credentials:'omit',cache:'no-store',signal:options.signal});
    const text=await response.text();
    let value:unknown;
    try {value=text?JSON.parse(text):undefined;} catch {throw new OpsError(response.status,{error:'invalid JSON response'});}
    if(!response.ok)throw new OpsError(response.status,value);
    return value as T;
  }
  request<O extends keyof Operations>(operation:O,input:RequestInput<O>):Promise<Operations[O]['response']> {
    const separator=operation.indexOf(' '),method=operation.slice(0,separator);
    let path=operation.slice(separator+1);
    const args=input as {path?:Record<string,unknown>;query?:Record<string,unknown>;header?:Record<string,string>;body?:unknown;signal?:AbortSignal};
    path=path.replace(/\{([^}]+)\}/g,(_,key)=>{
      if(args.path?.[key]===undefined)throw Error(`Missing path parameter ${key}`);
      return encodeURIComponent(String(args.path[key]));
    });
    const query=new URLSearchParams();
    for(const [key,value] of Object.entries(args.query??{})) if(value!==undefined) {
      if(Array.isArray(value))for(const item of value)query.append(key,String(item)); else query.set(key,String(value));
    }
    if(query.size)path+=`?${query}`;
    return this.#send(method,path,args.body,{signal:args.signal,headers:args.header});
  }
  #tokens(value:Schemas['privacy-proxy_internal_apimodels.AuthResponse']):Session {
    if(!value.access_token||!value.refresh_token)throw Error('OPS did not return a complete session');
    return {accessToken:value.access_token,refreshToken:value.refresh_token};
  }
  async loginServicePrincipal(providerAccessToken:string):Promise<Session> {
    const epoch=++this.#sessionEpoch;
    const value=await this.#send<Schemas['privacy-proxy_internal_apimodels.AuthResponse']>('POST','/api/v1/auth/azure/service-principal',{access_token:providerAccessToken},{anonymous:true});
    if(this.#sessionEpoch!==epoch)throw Error('Session changed while login was in progress');
    const session=this.#tokens(value); this.#session=session;return {...session};
  }
  refresh():Promise<Session> {
    const epoch=this.#sessionEpoch;
    if(this.#refresh?.epoch===epoch)return this.#refresh.promise;
    const original=this.#session;
    if(!original?.refreshToken)return Promise.reject(Error('No refresh token available'));
    const promise=this.#send<Schemas['privacy-proxy_internal_apimodels.AuthResponse']>('POST','/api/v1/refresh',{refresh_token:original.refreshToken},{anonymous:true})
      .then(value=>{
        const next=this.#tokens(value);
        if(this.#sessionEpoch!==epoch||this.#session!==original)throw Error('Session changed while refresh was in progress');
        this.#session=next;return {...next};
      }).finally(()=>{if(this.#refresh?.promise===promise)this.#refresh=undefined;});
    this.#refresh={epoch,promise};
    return promise;
  }
  #configurationBase(orgId:string,kind:ConfigurationKind):string {
    return kind==='platform'?'/api/v1/admin/configuration/platform':`/api/v1/admin/orgs/${encodeURIComponent(orgId)}/configuration/${encodeURIComponent(kind)}`;
  }
  context(orgId:string,kind:ConfigurationKind):Promise<ConfigurationContext> {return this.#send('GET',`${this.#configurationBase(orgId,kind)}/context`);}
  listRevisions(orgId:string,kind:ConfigurationKind):Promise<{revisions?:ConfigurationRevision[]}> {return this.#send('GET',`${this.#configurationBase(orgId,kind)}/revisions`);}
  revision(orgId:string,kind:ConfigurationKind,id:string):Promise<ConfigurationRevision> {return this.#send('GET',`${this.#configurationBase(orgId,kind)}/revisions/${encodeURIComponent(id)}`);}
  submitDraft(orgId:string,kind:ConfigurationKind,exactSource:string):Promise<ConfigurationRevision> {
    if(!this.#session)return Promise.reject(Error('A named session is required'));
    return this.#send('POST',`${this.#configurationBase(orgId,kind)}/revisions`,exactSource,{raw:true});
  }
  async reviewDraft(orgId:string,kind:ConfigurationKind,revisionId:string,coactivate:readonly string[]=[]):Promise<ReviewedConfiguration> {
    const captured=Object.freeze([...coactivate]);
    const review=await this.#send<ConfigurationReview>('POST',`${this.#configurationBase(orgId,kind)}/revisions/${encodeURIComponent(revisionId)}/simulate`,{coactivate:captured});
    const digests:Record<string,string>={};
    const ids=new Set<string>();
    for(const revision of review.revisions??[]) {
      if(!revision.id||!revision.kind||!revision.digest||digests[revision.kind]||ids.has(revision.id))throw Error('Invalid reviewed revision set');
      digests[revision.kind]=revision.digest;ids.add(revision.id);
    }
    if([...captured,revisionId].some(id=>!ids.has(id))||ids.size!==new Set([...captured,revisionId]).size)throw Error('Incomplete reviewed revision set');
    return Object.freeze({orgId,kind,revisionId,coactivate:captured,review,candidateDigests:Object.freeze(digests)});
  }
  activateReviewed(reviewed:ReviewedConfiguration):Promise<{revisions?:ConfigurationRevision[]}> {
    return this.#send('POST',`${this.#configurationBase(reviewed.orgId,reviewed.kind)}/revisions/${encodeURIComponent(reviewed.revisionId)}/activate`,{coactivate:reviewed.coactivate});
  }
  activateWithCI(reviewed:ReviewedConfiguration,approval:CIApproval):Promise<{revisions?:ConfigurationRevision[]}> {
    const given=approval.candidateDigests??{},expected=reviewed.candidateDigests;
    if(Object.keys(given).length!==Object.keys(expected).length||Object.entries(expected).some(([id,digest])=>given[id]!==digest))return Promise.reject(Error('CI approval does not match the reviewed candidate digests'));
    if(reviewed.kind==='platform')return Promise.reject(Error('Platform activation requires the named human approval route'));
    return this.#send('POST',`${this.#configurationBase(reviewed.orgId,reviewed.kind)}/revisions/${encodeURIComponent(reviewed.revisionId)}/activate-ci`,{coactivate:reviewed.coactivate,approval});
  }
  withdrawDraft(orgId:string,kind:ConfigurationKind,id:string):Promise<ConfigurationRevision> {return this.#send('POST',`${this.#configurationBase(orgId,kind)}/revisions/${encodeURIComponent(id)}/withdraw`);}
  preview(orgId:string,request:NodeSimulation):Promise<unknown> {return this.#send('POST',`/api/v1/admin/orgs/${encodeURIComponent(orgId)}/execution/simulate`,request);}
  readiness():Promise<Schemas['privacy-proxy_internal_apimodels.StatusResponse']> {return this.#send('GET','/api/v1/admin/status');}
  async rpc<T=unknown>(orgId:string,method:string,params:unknown[],options:{visibleTo?:string[];signal?:AbortSignal}={}):Promise<T> {
    const id=++this.#rpcId;
    const response=await this.#send<{jsonrpc?:string;id?:number;result?:T;error?:{code:number;message:string;data?:unknown}}>('POST',`/rpc/${encodeURIComponent(orgId)}`,{jsonrpc:'2.0',id,method,params,...(options.visibleTo?{visibleTo:options.visibleTo}:{})},{signal:options.signal});
    if(response.id!==id||response.jsonrpc!=='2.0')throw Error('Invalid JSON-RPC response binding');
    if(response.error)throw new RpcError(response.error.code,response.error.message,response.error.data);
    if(!Object.prototype.hasOwnProperty.call(response,'result'))throw Error('Missing JSON-RPC result');
    return response.result as T;
  }
  transactionStatus(hash:string,signal?:AbortSignal):Promise<TransactionProgress> {return this.#send('GET',`/api/v1/me/transactions/${encodeURIComponent(hash)}/execution`,undefined,{signal});}
  async waitForFinality(hash:string,options:{pollIntervalMs?:number;timeoutMs?:number;signal?:AbortSignal}={}):Promise<TransactionProgress> {
    const interval=options.pollIntervalMs??1000,timeout=options.timeoutMs??120000;
    if(interval<=0||timeout<=0)throw Error('Positive polling interval and timeout required');
    const signal=AbortSignal.any([AbortSignal.timeout(timeout),...(options.signal?[options.signal]:[])]);
    while(true) {
      signal.throwIfAborted();
      const status=await this.transactionStatus(hash,signal);
      if(status.reconciled&&status.execution?.finalized&&['included','reverted'].includes(status.status??''))return status;
      await new Promise<void>((resolve,reject)=>{
        const abort=()=>{clearTimeout(timer);reject(signal.reason);};
        const timer=setTimeout(()=>{signal.removeEventListener('abort',abort);resolve();},interval);
        signal.addEventListener('abort',abort,{once:true});
        if(signal.aborted)abort();
      });
    }
  }
}
