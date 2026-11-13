#include "hmac_ctap.h"
#include "hmac_enroll.h"
#include "hmac_assertion.h"
#include "hmac_store.h"
#include "crypto.h"
#include "cbor.h"
#include "state.h"
#include <string.h>

enum { ERR_INVALID_PARAMETER=0x02, ERR_MISSING_PARAMETER=0x14,
       ERR_UNSUPPORTED_ALG=0x26, ERR_CREDENTIAL_EXCLUDED=0x19,
       ERR_OPERATION_DENIED=0x27, ERR_UNSUPPORTED_OPTION=0x2b,
       ERR_NO_CREDENTIALS=0x2e, ERR_PIN_AUTH_INVALID=0x33, ERR_PIN_REQUIRED=0x36 };
static size_t error(uint8_t *out,size_t cap,uint8_t value) {
    if (!out || !cap) return 0;
    out[0]=value; return 1;
}
static bool text_eq(fj_cbor_reader *r,fj_cbor_item *it,const char *s) {
    uint8_t buf[32]; size_t n=0, expected=strlen(s);
    return it->type==FJ_CBOR_TSTR &&
           fj_cbor_read_bytes(r,it,buf,sizeof(buf),&n) && n==expected && memcmp(buf,s,n)==0;
}
static bool bstr(fj_cbor_reader *r,fj_cbor_item *it,uint8_t *out,size_t size) {
    size_t n=0; return it->type==FJ_CBOR_BSTR &&
        fj_cbor_read_bytes(r,it,out,size,&n) && n==size;
}
fj_hmac_route_t fj_hmac_ctap_classify(const uint8_t *msg,size_t len) {
    if (!msg || !len) return FJ_HMAC_ROUTE_INVALID;
    if (msg[0]!=1 && msg[0]!=2) return FJ_HMAC_ROUTE_NORMAL;
    fj_cbor_reader r; fj_cbor_item root; fj_cbor_reader_init(&r,msg+1,len-1);
    if (!fj_cbor_next(&r,&root) || root.type!=FJ_CBOR_MAP || root.val>32) return FJ_HMAC_ROUTE_INVALID;
    bool found=false, saw_hmac=false, saw_extensions=false;
    for (uint64_t i=0;i<root.val;i++) {
        fj_cbor_item k,v;
        if (!fj_cbor_next(&r,&k) || k.type!=FJ_CBOR_UINT || !fj_cbor_next(&r,&v)) return FJ_HMAC_ROUTE_INVALID;
        if (k.val==(msg[0]==1 ? 6u : 4u)) {
            if (saw_extensions || v.type!=FJ_CBOR_MAP || v.val>16) return FJ_HMAC_ROUTE_INVALID;
            saw_extensions=true;
            for (uint64_t j=0;j<v.val;j++) {
                fj_cbor_item name,value;
                if (!fj_cbor_next(&r,&name) || name.type!=FJ_CBOR_TSTR) return FJ_HMAC_ROUTE_INVALID;
                bool match=name.val==11 && name.start<=r.len && r.len-name.start>=11 &&
                           memcmp(r.buf+name.start,"hmac-secret",11)==0;
                if (!fj_cbor_skip(&r,&name) || !fj_cbor_next(&r,&value)) return FJ_HMAC_ROUTE_INVALID;
                if (match) {
                    if (saw_hmac) return FJ_HMAC_ROUTE_INVALID;
                    saw_hmac=true; found=true;
                    /* False in makeCredential requests means the extension
                     * was not requested and may use the normal path. */
                    if (msg[0]==1 && value.type==FJ_CBOR_BOOL && !value.val) found=false;
                }
                if (!fj_cbor_skip(&r,&value)) return FJ_HMAC_ROUTE_INVALID;
            }
        } else if (!fj_cbor_skip(&r,&v)) return FJ_HMAC_ROUTE_INVALID;
    }
    if (r.pos!=len-1) return FJ_HMAC_ROUTE_INVALID;
    return found ? FJ_HMAC_ROUTE_HMAC : FJ_HMAC_ROUTE_NORMAL;
}
static bool rp_map(fj_cbor_reader *r,const fj_cbor_item *m,uint8_t hash[32]) {
    if (m->type!=FJ_CBOR_MAP || m->val>16) return false;
    bool found=false;
    for (uint64_t i=0;i<m->val;i++) {
        fj_cbor_item k,v; if (!fj_cbor_next(r,&k)) return false;
        bool id=text_eq(r,&k,"id"); if (!fj_cbor_next(r,&v)) return false;
        if (id) {
            uint8_t name[64]; size_t n=0;
            if (found || v.type!=FJ_CBOR_TSTR ||
                !fj_cbor_read_bytes(r,&v,name,sizeof(name),&n) || n==0) return false;
            fj_sha256(name,n,hash); found=true;
        } else if (!fj_cbor_skip(r,&v)) return false;
    }
    return found;
}
static bool user_map(fj_cbor_reader *r,const fj_cbor_item *m) {
    if (m->type!=FJ_CBOR_MAP || m->val>16) return false;
    bool found=false;
    for (uint64_t i=0;i<m->val;i++) {
        fj_cbor_item k,v; if (!fj_cbor_next(r,&k)) return false;
        bool id=text_eq(r,&k,"id"); if (!fj_cbor_next(r,&v)) return false;
        if (id) {
            uint8_t identifier[64]; size_t n=0;
            if (found || v.type!=FJ_CBOR_BSTR ||
                !fj_cbor_read_bytes(r,&v,identifier,sizeof(identifier),&n) || !n) return false;
            found=true;
        } else if (!fj_cbor_skip(r,&v)) return false;
    }
    return found;
}
static bool options(fj_cbor_reader *r,const fj_cbor_item *m,bool *resident,bool *up,bool *uv) {
    if (m->type!=FJ_CBOR_MAP || m->val>16) return false;
    unsigned seen=0;
    for (uint64_t i=0;i<m->val;i++) {
        fj_cbor_item k,v; if (!fj_cbor_next(r,&k)) return false;
        uint8_t name[16]; size_t n=0;
        if (k.type!=FJ_CBOR_TSTR || !fj_cbor_read_bytes(r,&k,name,sizeof(name),&n) || !fj_cbor_next(r,&v)) return false;
        unsigned bit=n==2 && memcmp(name,"rk",2)==0 ? 1u : n==2 && memcmp(name,"up",2)==0 ? 2u : n==2 && memcmp(name,"uv",2)==0 ? 4u : 0u;
        if (bit) {
            if ((seen&bit) || v.type!=FJ_CBOR_BOOL) return false;
            seen|=bit; if (bit==1) *resident=v.val!=0; else if (bit==2) *up=v.val!=0; else *uv=v.val!=0;
        } else if (!fj_cbor_skip(r,&v)) return false;
    }
    return true;
}
static bool extensions(fj_cbor_reader *r,const fj_cbor_item *m,bool enroll,
                       bool *found,fj_hmac_request_t *request) {
    if (m->type!=FJ_CBOR_MAP || m->val>16) return false;
    for (uint64_t i=0;i<m->val;i++) {
        fj_cbor_item k,v; if (!fj_cbor_next(r,&k)) return false;
        bool match=text_eq(r,&k,"hmac-secret");
        if (!fj_cbor_next(r,&v)) return false;
        if (match) {
            if (*found) return false;
            *found=true;
            if (enroll) { if (v.type!=FJ_CBOR_BOOL || !v.val) return false; }
            else if (!fj_hmac_request_parse(r,&v,request)) return false;
        } else if (!fj_cbor_skip(r,&v)) return false;
    }
    return true;
}
static bool algorithms(fj_cbor_reader *r,const fj_cbor_item *a,bool *es256) {
    if (a->type!=FJ_CBOR_ARRAY || a->val>32) return false;
    for (uint64_t i=0;i<a->val;i++) {
        fj_cbor_item m; if (!fj_cbor_next(r,&m) || m.type!=FJ_CBOR_MAP || m.val>16) return false;
        bool type=false,alg=false; unsigned seen=0;
        for (uint64_t j=0;j<m.val;j++) {
            fj_cbor_item k,v; if (!fj_cbor_next(r,&k)) return false;
            uint8_t name[16]; size_t n=0;
            if (k.type!=FJ_CBOR_TSTR || !fj_cbor_read_bytes(r,&k,name,sizeof(name),&n) || !fj_cbor_next(r,&v)) return false;
            if (n==4 && memcmp(name,"type",4)==0) {
                if (seen&1u) return false;
                seen|=1u; type=text_eq(r,&v,"public-key");
            }
            else if (n==3 && memcmp(name,"alg",3)==0) {
                if (seen&2u) return false;
                seen|=2u; alg=v.type==FJ_CBOR_NEG && v.val==6;
                if (!fj_cbor_skip(r,&v)) return false;
            }
            else if (!fj_cbor_skip(r,&v)) return false;
        }
        if (type && alg) *es256=true;
    }
    return true;
}
static bool credentials(fj_cbor_reader *r,const fj_cbor_item *a,const uint8_t rp[32],
                        bool match_rp,const fj_hmac_ctap_context_t *ctx,
                        bool *found,uint8_t id[16]) {
    if (a->type!=FJ_CBOR_ARRAY || a->val>64) return false;
    for (uint64_t i=0;i<a->val;i++) {
        fj_cbor_item m; if (!fj_cbor_next(r,&m) || m.type!=FJ_CBOR_MAP || m.val>16) return false;
        uint8_t candidate[16]={0}; bool has_id=false,valid_id=false,type=false;
        for (uint64_t j=0;j<m.val;j++) {
            fj_cbor_item k,v; if (!fj_cbor_next(r,&k)) return false;
            uint8_t name[16]; size_t n=0;
            if (k.type!=FJ_CBOR_TSTR || !fj_cbor_read_bytes(r,&k,name,sizeof(name),&n) || !fj_cbor_next(r,&v)) return false;
            if (n==2 && memcmp(name,"id",2)==0) {
                if (has_id || v.type!=FJ_CBOR_BSTR) return false;
                has_id=true;
                if (v.val==16) { if (!bstr(r,&v,candidate,16)) return false; valid_id=true; }
                else if (!fj_cbor_skip(r,&v)) return false;
            } else if (n==4 && memcmp(name,"type",4)==0) {
                if (type || !text_eq(r,&v,"public-key")) return false;
                type=true;
            } else if (!fj_cbor_skip(r,&v)) return false;
        }
        if (has_id && valid_id && type) {
            fj_hmac_credential_t c;
            bool hmac_match=fj_hmac_store_get(candidate,&c) && (!match_rp || fj_ct_equal(c.rp_id_hash,rp,32));
            bool normal_match=!match_rp && ctx->normal_id_exists && ctx->normal_id_exists(ctx->normal_id_ctx,candidate);
            if (hmac_match || normal_match) {
                if (!*found) memcpy(id,candidate,16);
                *found=true;
            }
            fj_secure_zero(&c,sizeof(c));
        }
    }
    return true;
}
/* A pre-scan finds rpId before allow/exclude list regardless of CBOR order. */
static bool find_rp(const uint8_t *data,size_t len,bool enroll,uint8_t hash[32]) {
    fj_cbor_reader r; fj_cbor_item root; fj_cbor_reader_init(&r,data,len);
    if (!fj_cbor_next(&r,&root) || root.type!=FJ_CBOR_MAP || root.val>32) return false;
    bool found=false;
    for (uint64_t i=0;i<root.val;i++) {
        fj_cbor_item k,v;
        if (!fj_cbor_next(&r,&k) || k.type!=FJ_CBOR_UINT || !fj_cbor_next(&r,&v)) return false;
        if (k.val==(enroll ? 2u : 1u)) {
            if (found) return false;
            if (enroll) { if (!rp_map(&r,&v,hash)) return false; }
            else {
                uint8_t name[64]; size_t n=0;
                if (v.type!=FJ_CBOR_TSTR || !fj_cbor_read_bytes(&r,&v,name,sizeof(name),&n) || !n) return false;
                fj_sha256(name,n,hash);
            }
            found=true;
        } else if (!fj_cbor_skip(&r,&v)) return false;
    }
    return found && r.pos==len;
}
bool fj_hmac_ctap_preflight(const uint8_t *msg,size_t len,const fj_hmac_ctap_context_t *ctx,
                            uint8_t *out,size_t cap,size_t *written) {
    if (!msg || len<2 || msg[0]!=2 || !ctx || !ctx->policy || !out || !cap || !written) return false;
    uint8_t rp[32],client[32]={0},id[16]={0};
    if (!find_rp(msg+1,len-1,false,rp)) return false;
    fj_cbor_reader r; fj_cbor_item root; fj_cbor_reader_init(&r,msg+1,len-1);
    if (!fj_cbor_next(&r,&root) || root.type!=FJ_CBOR_MAP || root.val>32) return false;
    bool hash=false,found=false,has_list=false,has_options=false,up=true,uv=false,rk=false;
    uint32_t seen=0;
    for (uint64_t i=0;i<root.val;i++) {
        fj_cbor_item k,v;
        if (!fj_cbor_next(&r,&k) || k.type!=FJ_CBOR_UINT || !fj_cbor_next(&r,&v)) return false;
        if (k.val<=15) { uint32_t bit=1u<<(unsigned)k.val; if (seen&bit) return false; seen|=bit; }
        if (k.val==2) { if (!bstr(&r,&v,client,32)) return false; hash=true; }
        else if (k.val==3) { if (!credentials(&r,&v,rp,true,ctx,&found,id)) return false; has_list=true; }
        else if (k.val==5) { if (!options(&r,&v,&rk,&up,&uv)) return false; has_options=true; }
        else if (k.val==4 || k.val==6 || k.val==7) return false;
        else if (!fj_cbor_skip(&r,&v)) return false;
    }
    if (r.pos!=len-1 || !hash || !has_list || !has_options || up || uv || rk) return false;
    if (!found) {
        if (fj_state_get()==FJ_STATE_UNLOCKED) return false;
        *written=error(out,cap,ERR_NO_CREDENTIALS); return true;
    }
    fj_hmac_assertion_result_t result;
    if (!fj_hmac_preflight(id,rp,client,ctx->policy,ctx->mode,ctx->otp,&result)) {
        *written=error(out,cap,ERR_OPERATION_DENIED); return true;
    }
    fj_cbor_writer w; fj_cbor_writer_init(&w,out+1,cap-1);
    fj_cbor_map(&w,3); fj_cbor_uint(&w,1); fj_cbor_map(&w,2);
    fj_cbor_tstr(&w,"id"); fj_cbor_bstr(&w,id,16);
    fj_cbor_tstr(&w,"type"); fj_cbor_tstr(&w,"public-key");
    fj_cbor_uint(&w,2); fj_cbor_bstr(&w,result.auth_data,result.auth_data_len);
    fj_cbor_uint(&w,3); fj_cbor_bstr(&w,result.signature,result.signature_len);
    fj_secure_zero(&result,sizeof(result));
    *written=fj_cbor_ok(&w) ? (out[0]=0,w.len+1) : error(out,cap,ERR_INVALID_PARAMETER);
    return true;
}
size_t fj_hmac_ctap_dispatch(const uint8_t *msg,size_t len,const fj_hmac_ctap_context_t *ctx,
                             uint8_t *out,size_t cap) {
    if (!msg || len<2 || !ctx || !ctx->policy || !out || !cap) return error(out,cap,ERR_INVALID_PARAMETER);
    bool enroll=msg[0]==1;
    if ((!enroll && msg[0]!=2) || (enroll && !ctx->normal_id_exists)) return error(out,cap,ERR_INVALID_PARAMETER);
    uint8_t rp[32];
    if (!find_rp(msg+1,len-1,enroll,rp)) return error(out,cap,ERR_INVALID_PARAMETER);
    fj_cbor_reader r; fj_cbor_item root; fj_cbor_reader_init(&r,msg+1,len-1);
    if (!fj_cbor_next(&r,&root) || root.type!=FJ_CBOR_MAP || root.val>32) return error(out,cap,ERR_INVALID_PARAMETER);
    fj_hmac_assertion_request_t req={0}; memcpy(req.rp_id_hash,rp,32);
    bool ext=false,es=false,resident=false,up=true,uv=false,found=false,hash=false,pin=false,proto=false,user=false;
    uint32_t seen=0;
    for (uint64_t i=0;i<root.val;i++) {
        fj_cbor_item k,v; if (!fj_cbor_next(&r,&k) || k.type!=FJ_CBOR_UINT || !fj_cbor_next(&r,&v)) goto invalid;
        if (k.val<=15) { uint32_t bit=1u<<(unsigned)k.val; if (seen&bit) goto invalid; seen|=bit; }
        if (k.val==(enroll ? 1u : 2u)) { if (!bstr(&r,&v,req.client_data_hash,32)) goto invalid; hash=true; }
        else if (enroll && k.val==3) { if (!user_map(&r,&v)) goto invalid; user=true; }
        else if (enroll && k.val==4) { if (!algorithms(&r,&v,&es)) goto invalid; }
        else if (k.val==(enroll ? 5u : 3u)) { if (!credentials(&r,&v,rp,!enroll,ctx,&found,req.credential_id)) goto invalid; }
        else if (k.val==(enroll ? 6u : 4u)) { if (!extensions(&r,&v,enroll,&ext,&req.extension)) goto invalid; }
        else if (k.val==(enroll ? 7u : 5u)) { if (!options(&r,&v,&resident,&up,&uv)) goto invalid; }
        else if (k.val==(enroll ? 8u : 6u)) { if (!bstr(&r,&v,req.pin_auth,16)) goto invalid; pin=true; }
        else if (k.val==(enroll ? 9u : 7u)) { if (v.type!=FJ_CBOR_UINT || v.val!=1) goto invalid; proto=true; }
        else if (!fj_cbor_skip(&r,&v)) goto invalid;
    }
    if (r.pos!=len-1) goto invalid;
    if (!hash || !ext || (enroll && !user)) return error(out,cap,ERR_MISSING_PARAMETER);
    if (resident || (enroll && !up)) return error(out,cap,ERR_UNSUPPORTED_OPTION);
    if (pin!=proto) return error(out,cap,ERR_PIN_AUTH_INVALID);
    req.user_present=ctx->user_present; req.up_requested=up; req.uv_requested=uv; req.has_pin_auth=pin;
    if (enroll) {
        /* Ensure the full attestation fits before persisting a credential. */
        if (cap<230) return error(out,cap,ERR_INVALID_PARAMETER);
        if (!es) return error(out,cap,ERR_UNSUPPORTED_ALG);
        if (found) return error(out,cap,ERR_CREDENTIAL_EXCLUDED);
        if (uv && !pin) return error(out,cap,ERR_PIN_REQUIRED);
        fj_hmac_enroll_request_t er={0};
        memcpy(er.rp_id_hash,rp,32); memcpy(er.client_data_hash,req.client_data_hash,32);
        memcpy(er.pin_auth,req.pin_auth,16); er.user_present=ctx->user_present; er.has_pin_auth=pin;
        er.normal_id_exists=ctx->normal_id_exists; er.normal_id_ctx=ctx->normal_id_ctx;
        fj_hmac_enroll_result_t result;
        if (!fj_hmac_enroll(&er,ctx->mode,ctx->otp,&result)) return error(out,cap,ERR_OPERATION_DENIED);
        fj_cbor_writer w; fj_cbor_writer_init(&w,out+1,cap-1);
        fj_cbor_map(&w,3); fj_cbor_uint(&w,1); fj_cbor_tstr(&w,"none");
        fj_cbor_uint(&w,2); fj_cbor_bstr(&w,result.auth_data,result.auth_data_len);
        fj_cbor_uint(&w,3); fj_cbor_map(&w,0);
        fj_secure_zero(&result,sizeof(result));
        if (!fj_cbor_ok(&w)) return error(out,cap,ERR_INVALID_PARAMETER);
        out[0]=0; return w.len+1;
    }
    if (!found) return error(out,cap,ERR_NO_CREDENTIALS);
    fj_hmac_assertion_result_t result;
    if (!fj_hmac_assertion(&req,ctx->policy,ctx->mode,ctx->otp,&result)) return error(out,cap,ERR_OPERATION_DENIED);
    fj_cbor_writer w; fj_cbor_writer_init(&w,out+1,cap-1);
    fj_cbor_map(&w,3); fj_cbor_uint(&w,1); fj_cbor_map(&w,2);
    fj_cbor_tstr(&w,"id"); fj_cbor_bstr(&w,req.credential_id,16);
    fj_cbor_tstr(&w,"type"); fj_cbor_tstr(&w,"public-key");
    fj_cbor_uint(&w,2); fj_cbor_bstr(&w,result.auth_data,result.auth_data_len);
    fj_cbor_uint(&w,3); fj_cbor_bstr(&w,result.signature,result.signature_len);
    fj_secure_zero(&result,sizeof(result));
    if (!fj_cbor_ok(&w)) goto invalid;
    out[0]=0; return w.len+1;
invalid:
    return error(out,cap,ERR_INVALID_PARAMETER);
}
