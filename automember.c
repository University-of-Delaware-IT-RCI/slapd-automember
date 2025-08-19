/*
 * automember.c
 *
 * OpenLDAP overlay that synthesizes "member" attributes on group
 * directories (based on objectClass) by mapping "memberUid" attributes
 * to DNs with a fixed template.
 *
 */

#include "portable.h"
#include "slap.h"
#include "slap-config.h"

/* If no callbacks were specifically selected, enable the response
   callback: */
#if ! defined(AUTOMEMBER_CALLBACK_RESPONSE) && ! defined(AUTOMEMBER_CALLBACK_SEARCH)
#   define AUTOMEMBER_CALLBACK_RESPONSE
#endif

/* Provide a default value if the AUTOMEMBER_DEFAULT_SYNTH_TMPL macro
   wasn't defined externally: */
#ifndef AUTOMEMBER_DEFAULT_SYNTH_TMPL
#   define AUTOMEMBER_DEFAULT_SYNTH_TMPL "{}"
#endif
static const char *automember_default_synth_tmpl = AUTOMEMBER_DEFAULT_SYNTH_TMPL;

/* We need to dynamically add the memberOf attribute to the schema: */
static int
automember_memberof_attr_init(void)
{
    static AttributeDescription     *ad_memberOf = NULL;
    static const char               *ad_memberOf_desc =
                                        "( 1.2.840.113556.1.2.102 "
                                            "NAME 'memberOf' "
                                            "DESC 'Group that the entry belongs to' "
                                            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.12' "
                                            "EQUALITY distinguishedNameMatch "      /* added */
                                            "USAGE dSAOperation "                   /* added; questioned */
                                            "NO-USER-MODIFICATION "                 /* added */
                                            "X-ORIGIN 'iPlanet Delegated Administrator' )";
    static int                      has_been_called = 0;
    
    if ( ! has_been_called ) {
        int rc = register_at(ad_memberOf_desc, &ad_memberOf, 1);
        if ( rc && (rc != SLAP_SCHERR_ATTR_DUP) ) {
            Log(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "automember: automember_attr_init:  register_at('memberOf') failed (rc=%d)\n", rc);
            return rc;
        }
    }
    return LDAP_SUCCESS;
}

/* Per-overlay instance config */
typedef struct automember {
    AttributeDescription    *attr_oc;           /* The objectClass attribute def        */
    AttributeDescription    *attr_memberuid;    /* The attribute whose value(s) are
                                                   the source of synthesized values     */
    AttributeDescription    *attr_member;       /* Stash lookup of the 'member'
                                                   attribute                            */
    AttributeDescription    *attr_memberof;     /* Stash lookup of the 'memberOf'
                                                   attribute                            */
    AttributeDescription    *attr_uid;          /* Stash lookup of the 'uid' attribute  */
    ObjectClass             *oc_member;         /* The objectClass to which we add
                                                   the synthesized attribute            */
    ObjectClass             *oc_memberof;       /* The objectClass to which we add
                                                   the reverse-membership attribute     */
    const char              *synth_tmpl;        /* The string template that will be
                                                   used to create the target values    */
} automember_t;

/* Relative configuration OIDs */
enum {
    CFG_AUTOMEMBER_MEMBER_OBJECTCLASS = 1,
    CFG_AUTOMEMBER_SYNTHTMPL,
    CFG_AUTOMEMBER_MEMBEROF_OBJECTCLASS
};

/* Configuration handler: */
static int
automember_config(
    ConfigArgs  *c
)
{
    slap_overinst   *on = (slap_overinst*)c->bi;
    automember_t    *am = (automember_t*)on->on_bi.bi_private;
    const char      *text = NULL;
    
    switch ( c->op ) {
    
        case SLAP_CONFIG_EMIT:
            break;
        
        case LDAP_MOD_DELETE:
            break;
            
        default: {
            switch ( c->type ) {
                case CFG_AUTOMEMBER_MEMBER_OBJECTCLASS: {
                    if ( c->argc != 2 ) {
                        snprintf(c->cr_msg, sizeof(c->cr_msg),
                                 "automember: automember_config:  expects 'automember-member-objectClass <oc-name>'");
                        Debug(LDAP_DEBUG_CONFIG, "%s\n", c->cr_msg);
                        return 1;
                    }
                    am->oc_member = oc_find(c->argv[1]);
                    if ( ! am->oc_member ) {
                        snprintf(c->cr_msg, sizeof(c->cr_msg),
                                "automember: automember_config:  'member' objectClass '%s' is undefined", c->argv[1]);
                        Debug(LDAP_DEBUG_CONFIG, "%s\n", c->cr_msg);
                        return 1;
                    } else {
                        Debug(LDAP_DEBUG_CONFIG, "automember: automember_config:  automember_config: set 'member' objectClass %s\n", c->argv[1]);
                    }
                    break;
                }
                
                case CFG_AUTOMEMBER_MEMBEROF_OBJECTCLASS: {
                    if ( c->argc != 2 ) {
                        snprintf(c->cr_msg, sizeof(c->cr_msg),
                                 "automember: automember_config:  expects 'automember-memberof-objectClass <oc-name>'");
                        Debug(LDAP_DEBUG_CONFIG, "%s\n", c->cr_msg);
                        return 1;
                    }
                    am->oc_memberof = oc_find(c->argv[1]);
                    if ( ! am->oc_memberof ) {
                        snprintf(c->cr_msg, sizeof(c->cr_msg),
                                "automember: automember_config:  'memberof' objectClass '%s' is undefined", c->argv[1]);
                        Debug(LDAP_DEBUG_CONFIG, "%s\n", c->cr_msg);
                        return 1;
                    } else {
                        Debug(LDAP_DEBUG_CONFIG, "automember: automember_config:  automember_config: set 'memberof' objectClass %s\n", c->argv[1]);
                    }
                    break;
                }
                
                case CFG_AUTOMEMBER_SYNTHTMPL: {
                    const char  *arg_copy;
                    
                    if ( c->argc != 2 ) {
                        snprintf(c->cr_msg, sizeof(c->cr_msg),
                                 "automember: automember_config:  expects 'automember-synth-template <tmpl-string>'");
                        Debug(LDAP_DEBUG_CONFIG, "%s\n", c->cr_msg);
                        return 1;
                    }
                    arg_copy = ber_strdup(c->argv[1]);
                    if ( ! arg_copy ) {
                        snprintf(c->cr_msg, sizeof(c->cr_msg),
                                 "automember: automember_config:  failed to duplicate template string ");
                        Debug(LDAP_DEBUG_CONFIG, "%s\n", c->cr_msg);
                        return 1;
                    }
                    if ( am->synth_tmpl && am->synth_tmpl != automember_default_synth_tmpl ) ch_free((void*)am->synth_tmpl);
                    am->synth_tmpl = arg_copy;
                    Debug(LDAP_DEBUG_CONFIG, "automember: automember_config:  set synthtmpl %s\n", c->argv[1]);
                    break;
                }
            }
            break;
        }
    
    }
    return 0;
}

static ConfigTable automember_cfg[] = {
    { "automember-member-objectclass", "oc-name",
            2, 2, 0, ARG_MAGIC | CFG_AUTOMEMBER_MEMBER_OBJECTCLASS, automember_config,
            "( OLcfgOvAt:100.1 NAME 'olcAutomemberMemberObjectClass' "
                              "DESC 'Synthesize member attributes on entries of this class' "
                              "EQUALITY caseIgnoreMatch "
                              "SYNTAX OMsDirectoryString SINGLE-VALUE )",
            NULL, NULL },
    { "automember-synth-template", "tmpl-string",
            2, 2, 0, ARG_MAGIC | CFG_AUTOMEMBER_SYNTHTMPL, automember_config,
            "( OLcfgOvAt:100.2 NAME 'olcAutomemberSynthTemplate' "
                              "DESC 'string template for member synthesis' "
                              "SYNTAX OMsDirectoryString SINGLE-VALUE )",
            NULL, NULL },
    { "automember-memberof-objectclass", "oc-name",
            2, 2, 0, ARG_MAGIC | CFG_AUTOMEMBER_MEMBEROF_OBJECTCLASS, automember_config,
            "( OLcfgOvAt:100.3 NAME 'olcAutomemberMemberOfObjectClass' "
                              "DESC 'Synthesize memberOf attribute on entries of this class' "
                              "EQUALITY caseIgnoreMatch "
                              "SYNTAX OMsDirectoryString SINGLE-VALUE )",
            NULL, NULL },
    { NULL, NULL, 0, 0, 0, 0, NULL, NULL, NULL, NULL }
};

static ConfigOCs automember_ocs[] = {
    { "( OLcfgOvOc:100.0 NAME 'olcAutomemberConfig' "
                      "DESC 'Automember overlay configuration' "
                      "SUP olcOverlayConfig "
                      "MAY ( olcAutomemberMemberObjectClass $ olcAutomemberSynthTemplate $ olcAutomemberMemberOfObjectClass ) )",
            Cft_Overlay, automember_cfg, NULL, NULL },
    { NULL, 0, NULL }
};

/**************************/

/* Helper: transform the source attribute value into the
           synthesized value */
static BerValue*
automember_xform_uid_to_dn(
    Operation       *op,
    const char      *tmpl,
    BerValue        *src_val,
    BerValue        *out_val
)
{
    BerValue        *synth_val = NULL;
    const char      *s = tmpl;
    char            *b = NULL, *d;
    size_t          tmpl_len = strlen(tmpl);
    size_t          src_val_len = src_val->bv_val ? strlen(src_val->bv_val) : 0;
    int             n_tokens = 0;
    
    /* [SPECIAL CASE]  The source value is NULL: */
    if ( src_val == NULL ) {
        Debug(LDAP_DEBUG_TRACE, "automember: automember_xform_uid_to_dn:  NULL template yields NULL value\n");
        return NULL;
    }
    
    /* [SPECIAL CASE]  If the template is just "{}" then it's
       just duplication: */
    if ( strcmp(tmpl, "{}") == 0 ) {
        Debug(LDAP_DEBUG_TRACE, "automember: automember_xform_uid_to_dn:  trivial template duplicates original value\n");
        return ber_bvdup(src_val);
    }
    
    /* For every {} in the template, subtract 2 bytes and add
       the length of the src value: */
    while ( s && *s ) {
        const char  *p = strstr(s, "{}");
        
        if ( p ) {
            n_tokens++;
            tmpl_len -= 2;
            tmpl_len += src_val_len;
            p += 2;
        }
        s = p;
    }
    
    /* Allocate and fill-in the string: */
    b = (char*)ber_memalloc_x(tmpl_len + 1, op->o_tmpmemctx);
    if ( b ) {
        s = tmpl;
        d = b;
        while ( s && *s ) {
            char    *s2 = strstr(s, "{}");
            
            if ( s2 ) {
                /* Copy [s,s2-1] into d: */
                if ( s2 > s ) {
                    memcpy(d, s, s2 - s);
                    d += s2 - s;
                }
                /* Skip past the "{}" token: */
                s = s2 + 2;
                if ( src_val_len ) {
                    /* Copy the src value into place: */
                    memcpy(d, src_val->bv_val, src_val_len);
                    d += src_val_len;
                }
                *d = '\0';
            } else {
                /* Copy the remainder of s into d: */
                strcpy(d, s);
                s = NULL;
            }
        }
        /* The buffer at b now contains the templated C string; create
           a (duplicated) BerValue out of it: */
        if ( out_val ) {
            Debug(LDAP_DEBUG_TRACE, "automember: automember_xform_uid_to_dn: using pre-allocated BerValue for result\n");
            synth_val = out_val;
            synth_val->bv_len = tmpl_len;
            synth_val->bv_val = b;
        } else {
            Debug(LDAP_DEBUG_TRACE, "automember: automember_xform_uid_to_dn: allocated new BerValue for result\n");
            synth_val = ber_str2bv_x(b, 0, 0, NULL, op->o_tmpmemctx);
        }
        
        Debug(LDAP_DEBUG_TRACE, "automember: automember_xform_uid_to_dn: %d token(s) replaced, '%s' => '%s'\n", n_tokens, tmpl, b);
    }
    return synth_val;
}

/* Helper: fetch source attribute via internal search */
static Attribute*
automember_fetch_src_attr(
    Operation               *op,
    slap_overinst           *on,
    ObjectClass             *oc,
    BerValue                *ndn,
    AttributeDescription    *attr_memberuid
)
{
    Entry                   *e = NULL;
    Attribute               *src = NULL;
    Attribute               *ret = NULL;
    int                     rc;
    
    /* Read the entry from the underlying backend */
    rc = overlay_entry_get_ov(op,
                        ndn,
                        oc,             /* no filter */
                        attr_memberuid, /* limit to desired attribute only */
                        0,              /* rw */
                        &e,
                        on);
    if ( (rc == LDAP_SUCCESS) && (e != NULL) ) {
        /* Locate the source attribute on the fetched entry (user attrs) */
        src = attr_find(e->e_attrs, attr_memberuid);
        if ( src ) {
            /* Make an independent copy we can return to the caller */
            ret = attr_dup( src );
        }
        /* Always release the fetched entry */
        overlay_entry_release_ov(op, e, 0, on);
    }
    return ret; /* may be NULL if attr not present */
}

static int
automember_populate_member_attr(
    Operation           *op,
    SlapReply           *rs,
    slap_overinst       *on,
    automember_t        *am,
    int                 force_addition
)
{
    int                 rc = SLAP_CB_CONTINUE;
    Entry               *orig_e = rs->sr_entry, *e = NULL;
    int                 is_src_attr_requested = 0;
    int                 is_synth_attr_requested = 0;
    int                 is_src_operational = is_at_operational(am->attr_memberuid->ad_type) ? 1 : 0;
    int                 is_synth_operational = is_at_operational(am->attr_member->ad_type) ? 1 : 0;
    AttributeName       *an = op->ors_attrs;
    
    Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_member_attr:  an = %p; attr_is_operational = %d/%d; is_forced = %d\n",
                an, is_src_operational, is_synth_operational, force_addition);
    
    /* There's no point doing anything if the synth attribute wasn't
       requested: */
    if ( an == NULL ) {
        /* NULL ors_attrs implies "all user attributes" were
           requested, so the source attribute will be present if it
           is NOT operational, and synth is implied to have been
           requested if it is NOT operational: */
        is_synth_attr_requested = ! is_synth_operational;
        is_src_attr_requested = ! is_src_operational;
        Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_member_attr:  request is for all user attributes\n");
    } else {
        for ( ;
            an->an_name.bv_val && !(is_synth_attr_requested && is_src_attr_requested) ;
            an++
        ) {
            if ( bvmatch(&an->an_name, &slap_anlist_all_user_attributes[0].an_name) ) {
                /* All user attributes ("*") requested, update presence booleans
                   by OR'ing whether or not the attribute is NOT operational: */
                is_synth_attr_requested |= ! is_synth_operational;
                is_src_attr_requested |= ! is_src_operational;
                Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_member_attr:  request is for all user attributes\n");
            }
            else if ( bvmatch(&an->an_name, &slap_anlist_all_operational_attributes[0].an_name) )
            {
                /* All operational attributes ("+") requested, update presence booleans
                   by OR'ing whether or not the attribute is operational: */
                is_synth_attr_requested |= is_synth_operational;
                is_src_attr_requested |= is_src_operational;
                Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_member_attr:  request is for all operational attributes\n");
            }
            else if ( an->an_desc == am->attr_memberuid ) {
                /* The source attribute was explicitly requested: */
                is_src_attr_requested = 1;
                Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_member_attr:  source attribute explicitly requested\n");
            }
            else if ( an->an_desc == am->attr_member ) {
                /* The synth attribute was explicitly requested: */
                is_synth_attr_requested = 1;
                Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_member_attr:  synth attribute explicitly requested\n");
            }
        }
    }
    Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_member_attr:  attr_is_requested = %d/%d\n",
                is_src_attr_requested, is_synth_attr_requested);
    if ( force_addition || is_synth_attr_requested ) {
        Attribute   *src = attr_find(orig_e->e_attrs, am->attr_memberuid);
        Attribute   *dst = attr_find(orig_e->e_attrs, am->attr_member);
        
        if ( ! dst ) {
            if ( ! is_src_attr_requested ) {
                Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_member_attr:  fetching source attribute (was not requested)\n");
                src = automember_fetch_src_attr(op, on, am->oc_member, &orig_e->e_nname, am->attr_memberuid);
                if ( ! src ) {
                    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "automember: automember_populate_member_attr:  unable to fetch full object\n");
                }
            }
            /* Add synthesized attribute if we have source values */
            if ( src ) {
                if ( src->a_vals ) {
                    int         attr_idx, out_idx;
                    BerVarray   dst_vals = NULL;
                    
                    /* Count the number of attributes we're going to transform: */
                    for ( attr_idx=0; src->a_vals[attr_idx].bv_val; attr_idx++ );
                    Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_member_attr:  source attribute located, %d value(s)\n", attr_idx);
                    
                    /* Allocate the BerVarray: */
                    dst_vals = (BerVarray)ber_memalloc_x((attr_idx + 1) * sizeof(struct berval), op->o_tmpmemctx);
                    if ( dst_vals ) {
                        for ( attr_idx=0, out_idx=0; src->a_vals[attr_idx].bv_val; attr_idx++ ) {
                            if ( automember_xform_uid_to_dn(op, am->synth_tmpl, &src->a_vals[attr_idx], &dst_vals[out_idx]) ) {
                                out_idx++;
                                Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_member_attr:  added transform of attribute value '%s'\n",
                                            src->a_vals[attr_idx].bv_val);
                            } else {
                                Log(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "automember: automember_populate_member_attr:  failed to transform attribute value '%s'\n",
                                            src->a_vals[attr_idx].bv_val);
                            }
                        }
                        if ( out_idx > 0 ) {
                            /* Set the list terminator sentinel: */
                            BER_BVZERO(&dst_vals[out_idx]);
                            
                            if ( out_idx < attr_idx ) {
                                Log(LDAP_DEBUG_ANY, LDAP_LEVEL_WARNING, "automember: automember_populate_member_attr:  expected %d value(s), produced %d\n", attr_idx, out_idx);
                            }
                            
                            
                            /* Add the new attribute: */
                            e = ( rs->sr_flags & REP_ENTRY_MODIFIABLE ) ? orig_e : entry_dup(orig_e);
                            if ( attr_merge(e, am->attr_member, dst_vals, NULL) != 0 ) {
                                Log(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "automember: automember_populate_member_attr:  failed to append member attribute to entry\n");
                            }
                            if ( e != orig_e ) {
                                rs_replace_entry(op, rs, on, e);
                                rs->sr_flags &= ~REP_ENTRY_MASK;
                                rs->sr_flags |= REP_ENTRY_MODIFIABLE | REP_ENTRY_MUSTBEFREED;
                            }
                        } else {
                            Log(LDAP_DEBUG_ANY, LDAP_LEVEL_WARNING, "automember: automember_populate_member_attr:  expected %d value(s), produced none\n", attr_idx);
                        }
                        /* Release the value array: */
                        ber_bvarray_free_x(dst_vals, op->o_tmpmemctx);
                    } else {
                        Log(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "automember: automember_populate_member_attr:  failed to allocate member attribute value array\n");
                    }
                } else {
                    Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_member_attr:  empty source values list\n");
                }
                if ( ! is_src_attr_requested ) attr_free(src);
            }
        } else {
            Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_member_attr:  synth attribute already present in reply payload\n");
        }
    }
    return rc;
}

struct automember_collect_memberof_context {
    BerVarray   *dn_list;
    void        *memctx;
};

static int
automember_collect_memberof_dn_per_entry(
    Operation       *op,
    SlapReply       *rs
)
{
    struct automember_collect_memberof_context  *sc_ctxt = (struct automember_collect_memberof_context*)op->o_callback->sc_private;

    Debug(LDAP_DEBUG_TRACE, "automember: automember_collect_memberof_dn_per_entry:  new entry found %p\n", rs->sr_entry);
    if ( (rs->sr_type == REP_SEARCH) && rs->sr_entry ) {
        int         n = 0;
        BerVarray   dn_list = *(sc_ctxt->dn_list);

        if (dn_list) while (!BER_BVISNULL(&dn_list[n])) n++;
        
        /* Reallocate the ber array with an additional slot: */
        dn_list = (BerVarray)ber_memrealloc_x(dn_list, (n + 2) * sizeof(struct berval), sc_ctxt->memctx);
        /* Add the new value to the list and set the list terminator sentinel: */
        ber_dupbv_x(&dn_list[n], &rs->sr_entry->e_name, sc_ctxt->memctx);
        BER_BVZERO(&dn_list[n+1]);
        
        /* On realloc, the dn_list pointer may have changed -- reset
           it in the callback context struct: */
        *(sc_ctxt->dn_list) = dn_list;
    }
    return LDAP_SUCCESS;
}

static int
automember_collect_memberof_dn(
    Operation           *op,
    ObjectClass         *oc,
    struct berval       *uid_value,
    BerVarray           *out_dn_list
)
{
    static const char   *filter_fmt = "(&(objectClass=%s)(memberUid=%s))";
    slap_overinst       *on = (slap_overinst*)op->o_bd->bd_info;
    BackendDB           be = *op->o_bd;
    struct berval       filter_str;
    Filter              *filter;
    BerVarray           dn_list = NULL;
    int                 rc;
    
    /* Start by making sure nothing is returned by default... */    
    *out_dn_list = NULL;
    
    /* Preconditions:  uid_value is non-NULL and has a string value. */
    filter_str.bv_len = strlen(filter_fmt) - 4 + strlen(oc->soc_cname.bv_val) + strlen(uid_value->bv_val);
    filter_str.bv_val = (char*)ber_memalloc_x(filter_str.bv_len + 1, op->o_tmpmemctx);
    if ( filter_str.bv_val == NULL ) {
        Log(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "automember: automember_collect_memberof_dn:  unable to allocate filter berval\n");
        return LDAP_OTHER;
    }
    rc = snprintf(filter_str.bv_val, filter_str.bv_len + 1, filter_fmt, oc->soc_cname.bv_val, uid_value->bv_val);
    if ( rc > filter_str.bv_len ) {
        ber_memfree_x(filter_str.bv_val, op->o_tmpmemctx);
        Log(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "automember: automember_collect_memberof_dn:  unexpected overflow of filter berval buffer\n");
        return LDAP_OTHER;
    }
    Debug(LDAP_DEBUG_TRACE, "automember: automember_collect_memberof_dn:  search filter string '%s' created\n", filter_str.bv_val);
    
    /* Create the filter from the string: */
    filter = str2filter_x(op, filter_str.bv_val);
    if ( filter ) {
        Operation                                   op2 = *op;
        SlapReply                                   rs2 = { REP_RESULT };
        slap_callback                               sc = {0};
        struct automember_collect_memberof_context  sc_ctxt;
        
        op2.o_bd            = &be;                        /* use current backend */
        op2.o_bd->bd_info   = (BackendInfo*)on->on_info;
        
        op2.o_tag           = LDAP_REQ_SEARCH;
        op2.o_req_dn        = op->o_bd->be_suffix[0];
        op2.o_req_ndn       = op->o_bd->be_nsuffix[0];
        op2.o_dn            = op->o_bd->be_rootdn;
        op2.o_ndn           = op->o_bd->be_rootndn;
        op2.ors_scope       = LDAP_SCOPE_SUBTREE;
        op2.ors_deref       = LDAP_DEREF_NEVER;
        op2.ors_slimit      = SLAP_NO_LIMIT;
        op2.ors_tlimit      = SLAP_NO_LIMIT;
        op2.ors_attrs       = slap_anlist_no_attrs;      /* DNs only */
        op2.ors_attrsonly   = 0;
        op2.o_do_not_cache  = 1;
        op2.ors_filter      = filter;
        op2.ors_filterstr   = filter_str;
        
        /* Get our search callback context setup, so we can add DNs to the list: */
        sc_ctxt.dn_list     = &dn_list;
        sc_ctxt.memctx      = op->o_tmpmemctx;   /* Use the parent operation's temp context */
        sc.sc_private       = &sc_ctxt;
        sc.sc_response      = automember_collect_memberof_dn_per_entry;
        op2.o_callback      = &sc;
        
        Debug(LDAP_DEBUG_TRACE, "automember: automember_collect_memberof_dn:  search operation initialized\n");
        
        /* Perform the search: */
        rc = op2.o_bd->be_search(&op2, &rs2);
        Debug(LDAP_DEBUG_TRACE, "automember: automember_collect_memberof_dn:  search operation completed (rc=%d)\n", rc);
        
        /* Dispose of the filter and operation: */
        filter_free_x(op, filter, 1);
        ber_memfree_x(filter_str.bv_val, op->o_tmpmemctx);
        
        /* Return the dn_list: */
        if ( rc == LDAP_SUCCESS ) {
            *out_dn_list = dn_list;
        } else {
            if ( dn_list ) ber_bvarray_free_x(dn_list, op->o_tmpmemctx);
        }
    } else {
        ber_memfree_x(filter_str.bv_val, op->o_tmpmemctx);
        Log(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "automember: automember_collect_memberof_dn:  unable to allocate filter\n");
        return LDAP_OTHER;
    }
    return LDAP_SUCCESS;
}

static int
automember_populate_memberof_attr(
    Operation           *op,
    SlapReply           *rs,
    slap_overinst       *on,
    automember_t        *am,
    int                 force_addition
)
{
    int                 rc = SLAP_CB_CONTINUE;
    Entry               *orig_e = rs->sr_entry, *e = NULL;
    int                 is_synth_attr_requested = 0;
    int                 is_synth_operational = is_at_operational(am->attr_memberof->ad_type) ? 1 : 0;
    AttributeName       *an = op->ors_attrs;
    
    Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_memberof_attr:  an = %p; attr_is_operational = %d; is_forced = %d\n",
                an, is_synth_operational, force_addition);
    
    /* There's no point doing anything if the synth attribute wasn't
       requested: */
    if ( an == NULL ) {
        /* NULL ors_attrs implies "all user attributes" were
           requested, so the source attribute will be present if it
           is NOT operational, and synth is implied to have been
           requested if it is NOT operational: */
        is_synth_attr_requested = ! is_synth_operational;
        Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_memberof_attr:  request is for all user attributes\n");
    } else {
        for ( ;
            an->an_name.bv_val && !is_synth_attr_requested ;
            an++
        ) {
            if ( bvmatch(&an->an_name, &slap_anlist_all_user_attributes[0].an_name) ) {
                /* All user attributes ("*") requested, update presence booleans
                   by OR'ing whether or not the attribute is NOT operational: */
                is_synth_attr_requested |= ! is_synth_operational;
                Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_memberof_attr:  request is for all user attributes\n");
            }
            else if ( bvmatch(&an->an_name, &slap_anlist_all_operational_attributes[0].an_name) )
            {
                /* All operational attributes ("+") requested, update presence booleans
                   by OR'ing whether or not the attribute is operational: */
                is_synth_attr_requested |= is_synth_operational;
                Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_memberof_attr:  request is for all operational attributes\n");
            }
            else if ( an->an_desc == am->attr_memberof ) {
                /* The synth attribute was explicitly requested: */
                is_synth_attr_requested = 1;
                Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_memberof_attr:  synth attribute explicitly requested\n");
            }
        }
    }
    Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_memberof_attr:  attr_is_requested = %d\n", is_synth_attr_requested);
    
    if ( force_addition || is_synth_attr_requested ) {
        Attribute               *uid = attr_find(orig_e->e_attrs, am->attr_uid);
        Attribute               *memberof = attr_find(orig_e->e_attrs, am->attr_memberof);
        
        if ( memberof == NULL ) {
            BerVarray               dn_list = NULL;
            int                     attr_idx;
            
            if ( uid == NULL ) {
                Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "automember: automember_populate_memberof_attr:  no memberUid attribute on entry\n");
                return SLAP_CB_CONTINUE;
            }
            if ( ! uid->a_vals || ! uid->a_vals[0].bv_val ) {
                /* Empty attribute list: */
                Log(LDAP_DEBUG_ANY, LDAP_LEVEL_INFO, "automember: automember_populate_memberof_attr:  no memberUid attribute values on entry\n");
                return SLAP_CB_CONTINUE;
            }
            /* Count how many attribute values: */
            for ( attr_idx=0; uid->a_vals[attr_idx].bv_val; attr_idx++ );
            if ( attr_idx > 1 ) {
                /* Too many values in attribute list: */
                Log(LDAP_DEBUG_ANY, LDAP_LEVEL_WARNING, "automember: automember_populate_memberof_attr:  too many memberUid attribute values (%d)\n", attr_idx);
                return SLAP_CB_CONTINUE;
            }
            Debug(LDAP_DEBUG_TRACE, "automember: automember_populate_memberof_attr:  lookup group memberships for uid '%s'\n", uid->a_vals[0].bv_val);
            
            /* We're ready to lookup group memberships for this user: */
            rc = automember_collect_memberof_dn(op, am->oc_member, &uid->a_vals[0], &dn_list);
            if ( (rc == LDAP_SUCCESS) && dn_list ) {                
                e = ( rs->sr_flags & REP_ENTRY_MODIFIABLE ) ? orig_e : entry_dup(orig_e);
            
                /* Add the memberOf attributes: */
                if ( attr_merge(e, am->attr_memberof, dn_list, NULL) != 0 ) {
                    Log(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "automember: automember_populate_member_attr:  failed to append memberOf attribute to entry\n");
                }
                if ( e != orig_e ) {
                    rs_replace_entry(op, rs, on, e);
                    rs->sr_flags &= ~REP_ENTRY_MASK;
                    rs->sr_flags |= REP_ENTRY_MODIFIABLE | REP_ENTRY_MUSTBEFREED;
                }                
                ber_bvarray_free_x(dn_list, op->o_tmpmemctx);
            }
            rc = SLAP_CB_CONTINUE;
        }
    }
    return rc;
}

#ifdef AUTOMEMBER_CALLBACK_RESPONSE

    /* Response handler */
    static int
    automember_response(
        Operation       *op,
        SlapReply       *rs
    )
    {
        slap_overinst   *on = (slap_overinst*)op->o_bd->bd_info;
        automember_t    *am = (automember_t *)on->on_bi.bi_private;
        int             rc = SLAP_CB_CONTINUE;
        
        Debug(LDAP_DEBUG_TRACE, "automember: automember_response:  %p %p %p %p\n", am->attr_oc, am->attr_memberuid, am->attr_member, am->oc_member);
        
        /* If we aren't configured, don't do anything: */
        if ( ! (am->attr_oc && am->attr_memberuid && am->attr_member && am->synth_tmpl && am->oc_member) ) return SLAP_CB_CONTINUE;
        
        Debug(LDAP_DEBUG_TRACE, "automember: automember_response:  type = %d, entry = %p\n", rs->sr_type, rs->sr_entry);
        
        /* React to searches that produced non-empty results of the correct objectClass : */
        if ( (rs->sr_type == REP_SEARCH) && (rs->sr_entry != NULL) ) {
            if ( am->oc_member && is_entry_objectclass_or_sub(rs->sr_entry, am->oc_member) ) {
                if ( am->attr_memberuid && am->attr_member && am->synth_tmpl ) {
                    rc = automember_populate_member_attr(
                                op,
                                rs,
                                on,
                                am,
                                0 /* force addition */);
                }
            }
            else if ( am->oc_memberof && is_entry_objectclass_or_sub(rs->sr_entry, am->oc_memberof) ) {
                if ( am->attr_uid && am->attr_memberof ) {
                    rc = automember_populate_memberof_attr(
                                op,
                                rs,
                                on,
                                am,
                                0 /* force addition */);
                }
            }
        }
        return rc;
    }

#endif

#ifdef AUTOMEMBER_CALLBACK_SEARCH
    
    static int
    automember_search_cb(
        Operation           *op,
        SlapReply           *rs
    )
    {
        slap_overinst       *on = (slap_overinst *)((slap_callback *)op->o_callback)->sc_private;
        automember_t        *am = (automember_t *)on->on_bi.bi_private;
        int                 rc = SLAP_CB_CONTINUE;
        
        Debug(LDAP_DEBUG_TRACE, "automember: automember_search_cb:  %p %p %p %p\n", op, rs, on, am);
        
        /* If we aren't configured, don't do anything: */
        if ( ! (am->attr_oc && am->attr_memberuid && am->attr_member && am->synth_tmpl && am->oc_member) ) return SLAP_CB_CONTINUE;
        
        Debug(LDAP_DEBUG_TRACE, "automember: automember_search_cb:  type = %d, entry = %p\n", rs->sr_type, rs->sr_entry);
        
        /* React to searches that produced non-empty results of the correct objectClass : */
        if ( rs->sr_entry != NULL ) {
            if ( am->oc_member && is_entry_objectclass_or_sub(rs->sr_entry, am->oc_member) ) {
                if ( am->attr_memberuid && am->attr_member && am->synth_tmpl ) {
                    rc = automember_populate_member_attr(
                                op,
                                rs,
                                on,
                                am,
                                1 /* force addition */);
                }
            }
            else if ( am->oc_memberof && is_entry_objectclass_or_sub(rs->sr_entry, am->oc_memberof) ) {
                if ( am->attr_uid && am->attr_memberof ) {
                    rc = automember_populate_memberof_attr(
                                op,
                                rs,
                                on,
                                am,
                                1 /* force addition */);
                }
            }
        }
        return rc;
    }
    
    static int
    automember_search(
        Operation           *op,
        SlapReply           *rs
    )
    {
        slap_overinst       *on = (slap_overinst*)op->o_bd->bd_info;
        automember_t        *am = (automember_t *)on->on_bi.bi_private;
        
        Debug(LDAP_DEBUG_TRACE, "automember: automember_search:  %p %p %p %p %p\n", op, rs, on, am, rs->sr_entry);
        
        if ( am->oc_member || am->oc_memberof ) {
            /* Chain to the next backend with our callback in place */
            slap_callback       *sc = op->o_tmpcalloc(1, sizeof(slap_callback), op->o_tmpmemctx);
            
            Debug(LDAP_DEBUG_TRACE, "automember: automember_search:  callback allocated %p (existing callback %p)\n", sc, op->o_callback);
            
            sc->sc_response = automember_search_cb;
            sc->sc_private  = on;
            sc->sc_next     = op->o_callback;
            op->o_callback  = sc;
            
            Debug(LDAP_DEBUG_TRACE, "automember: automember_search:  callback linked into op chain\n", sc);
        }    
        return SLAP_CB_CONTINUE;
    }

#endif

/**************************/

static int
automember_db_init(
    BackendDB       *be,
    ConfigReply     *cr
)
{
    slap_overinst   *on = (slap_overinst *)be->bd_info;
    automember_t    *am = (automember_t*)ch_calloc(1, sizeof(automember_t));
    const char      *text = NULL;
    int             rc;
    
    if (slap_str2ad("objectClass", &am->attr_oc, &text) != LDAP_SUCCESS) {
        ch_free(am);
        Log(LDAP_DEBUG_ANY, LDAP_LEVEL_ERR, "automember: unable to resolve objectClass attribute\n");
        return 1;
    }
    Debug(LDAP_DEBUG_TRACE, "automember: automember_db_init:  objectClass attribute found\n");
    
    rc = slap_str2ad("memberuid", &am->attr_memberuid, &text);
    if ( rc != LDAP_SUCCESS) {
        ch_free(am);
        Debug(LDAP_DEBUG_CONFIG, "automember: automember_config:  unable to find 'memberUid' attribute (rc=%d)\n", rc);
        return 1;
    }
    Debug(LDAP_DEBUG_TRACE, "automember: automember_db_init:  memberUid attribute found\n");
    
    rc = slap_str2ad("member", &am->attr_member, &text);
    if ( rc != LDAP_SUCCESS) {
        ch_free(am);
        Debug(LDAP_DEBUG_CONFIG, "automember: automember_config:  unable to find 'member' attribute (rc=%d)\n", rc);
        return 1;
    }
    Debug(LDAP_DEBUG_TRACE, "automember: automember_db_init:  member attribute found\n");
    
    rc = slap_str2ad("memberof", &am->attr_memberof, &text);
    if ( rc != LDAP_SUCCESS) {
        ch_free(am);
        Debug(LDAP_DEBUG_CONFIG, "automember: automember_config:  unable to find 'memberOf' attribute (rc=%d)\n", rc);
        return 1;
    }
    Debug(LDAP_DEBUG_TRACE, "automember: automember_db_init:  memberOf attribute found\n");
    
    rc = slap_str2ad("uid", &am->attr_uid, &text);
    if ( rc != LDAP_SUCCESS) {
        ch_free(am);
        Debug(LDAP_DEBUG_CONFIG, "automember: automember_config:  unable to find 'uid' attribute (rc=%d)\n", rc);
        return 1;
    }
    Debug(LDAP_DEBUG_TRACE, "automember: automember_db_init:  uid attribute found\n");
    
    am->synth_tmpl = automember_default_synth_tmpl;
    on->on_bi.bi_private = am;
    return 0;
}

static int
automember_db_destroy(
    BackendDB       *be,
    ConfigReply     *cr
)
{
    slap_overinst   *on = (slap_overinst *)be->bd_info;
    automember_t    *am = (automember_t*)on->on_bi.bi_private;
    
    if ( am ) {
        on->on_bi.bi_private = NULL;
        
        if ( am->synth_tmpl && am->synth_tmpl != automember_default_synth_tmpl ) {
            Debug(LDAP_DEBUG_TRACE, "automember: automember_db_destroy: destroying synth_tmpl\n");
            ch_free((void*)am->synth_tmpl);
        }
        Debug(LDAP_DEBUG_TRACE, "automember: automember_db_destroy: destroying config\n");
        ch_free(am);
    }
    return 0;
}

/* The overlay registration record */
static slap_overinst automember;

/* Initialize overlay */
#if SLAPD_OVER_AUTOMEMBER == SLAPD_MOD_DYNAMIC
static
#endif /* SLAPD_OVER_AUTOMEMBER == SLAPD_MOD_DYNAMIC */
int
automember_initialize(void)
{
    int             rc = automember_memberof_attr_init();
    
    if ( rc == LDAP_SUCCESS ) {
        automember.on_bi.bi_type = "automember";
        
        automember.on_bi.bi_db_init = automember_db_init;
        automember.on_bi.bi_db_destroy = automember_db_destroy;

#ifdef AUTOMEMBER_CALLBACK_RESPONSE
        automember.on_response = automember_response;
#endif

#ifdef AUTOMEMBER_CALLBACK_SEARCH
        automember.on_bi.bi_op_search = automember_search;
#endif
    
        automember.on_bi.bi_cf_ocs = automember_ocs;
        rc = config_register_schema( automember_cfg, automember_ocs );
        if ( rc == 0 ) {
            rc = overlay_register(&automember);
        }
    }
    return rc;
}

#if SLAPD_OVER_AUTOMEMBER == SLAPD_MOD_DYNAMIC
int
init_module(
    int         argc,
    char        *argv[]
)
{
    return automember_initialize();
}
#endif
