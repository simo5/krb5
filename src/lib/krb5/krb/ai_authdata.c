/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2010 by the Massachusetts Institute of Technology.  All
 * Rights Reserved.
 * Copyright 2015 Red Hat, Inc.  All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

#include "k5-int.h"
#include "authdata.h"
#include "auth_con.h"
#include "int-proto.h"

/*
 * Authdata backend for processing SignedPath. Presently does not handle
 * the equivalent information in [MS-PAC], as that would require an NDR
 * interpreter.
 */

struct authind_context {
    int count;
    krb5_data *indicators;
    krb5_boolean authenticated;
};

static krb5_error_code
authind_init(krb5_context kcontext, void **plugin_context)
{
    *plugin_context = NULL;
    return 0;
}

static void
authind_flags(krb5_context kcontext,
              void *plugin_context,
              krb5_authdatatype ad_type,
              krb5_flags *flags)
{
    *flags = AD_CAMMAC_PROTECTED;
}

static void
authind_fini(krb5_context kcontext, void *plugin_context)
{
    return;
}

static krb5_error_code
authind_request_init(krb5_context kcontext,
                       krb5_authdata_context context,
                       void *plugin_context,
                       void **request_context)
{
    krb5_error_code code;
    struct authind_context *aictx;

    aictx = k5alloc(sizeof(*aictx), &code);
    if (aictx == NULL)
        return code;

    aictx->indicators = NULL;
    aictx->authenticated = FALSE;

    *request_context = aictx;

    return 0;
}

static void
authind_free_indicators(krb5_context kcontext,
                        int *count, krb5_data **ptr)
{
    krb5_data *indicators = *ptr;
    int num = *count;
    int i;

    for (i = 0; i < num; i++)
        krb5_free_data_contents(kcontext, &indicators[i]);
    }
    free(indicators);
    *count = 0;
    *ptr = NULL;
}

static krb5_error_code
authind_import_authdata(krb5_context kcontext,
                          krb5_authdata_context context,
                          void *plugin_context,
                          void *request_context,
                          krb5_authdata **authdata,
                          krb5_boolean kdc_issued,
                          krb5_const_principal kdc_issuer)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code code;
    krb5_data enc_sp;

    enc_sp.data = (char *)authdata[0]->contents;
    enc_sp.length = authdata[0]->length;

    code = decode_krb5_ad_signedpath(&enc_sp, &sp);
    if (code != 0)
        return code;

    authind_free_indicators(kcontext, &aictx->count, &aictx->indicators);

    krb5_free_ad_signedpath(kcontext, sp);

    aictx->authenticated = TRUE;

    return 0;
}


static krb5_error_code
authind_export_authdata(krb5_context kcontext,
                          krb5_authdata_context context,
                          void *plugin_context,
                          void *request_context,
                          krb5_flags usage,
                          krb5_authdata ***out_authdata)
{
    struct authind_context *s4uctx = (struct authind_context *)request_context;
    krb5_error_code code;
    krb5_authdata **authdata;
    krb5_data *data;

    if (s4uctx->count == 0)
        return 0;

    memset(&sp, 0, sizeof(sp));
    sp.delegated = s4uctx->delegated;

    authdata = k5calloc(2, sizeof(krb5_authdata *), &code);
    if (authdata == NULL)
        return code;

    authdata[0] = k5alloc(sizeof(krb5_authdata), &code);
    if (authdata[0] == NULL)
        return code;

    code = encode_krb5_ad_signedpath(&sp, &data);
    if (code != 0) {
        krb5_free_authdata(kcontext, authdata);
        return code;
    }

    authdata[0]->magic = KV5M_AUTHDATA;
    authdata[0]->ad_type = KRB5_AUTHDATA_SIGNTICKET;
    authdata[0]->length = data->length;
    authdata[0]->contents = (krb5_octet *)data->data;

    authdata[1] = NULL;

    free(data);

    *out_authdata = authdata;

    return 0;
}


static krb5_error_code
authind_verify(krb5_context kcontext,
                 krb5_authdata_context context,
                 void *plugin_context,
                 void *request_context,
                 const krb5_auth_context *auth_context,
                 const krb5_keyblock *key,
                 const krb5_ap_req *req)
{
    /*
     * XXX there is no way to verify the SignedPath without the TGS
     * key. This means that we can never mark this as authenticated.
     */

    return 0;
}

static void
authind_request_fini(krb5_context kcontext,
                       krb5_authdata_context context,
                       void *plugin_context,
                       void *request_context)
{
    struct authind_context *aictx = (struct authind_context *)request_context;

    if (aictx == NULL)
        return;

    authind_free_indicators(kcontext, &aictx->count, &aictx->indicators);
    free(aictx);
}


static krb5_data authentication_indicators_attr = {
    KV5M_DATA,
    sizeof("urn:authentication-indicators:indicators") - 1,
    "urn:authentication-indicators:indicators"
};

static krb5_error_code
authind_get_attribute_types(krb5_context kcontext,
                            krb5_authdata_context context,
                            void *plugin_context,
                            void *request_context,
                            krb5_data **out_attrs)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code code;
    krb5_data *attrs;
    int i = 0;

    if (aictx->count == 0)
        return ENOENT;

    attrs = k5calloc(2, sizeof(krb5_data), &code);
    if (attrs == NULL)
        goto cleanup;

    code = krb5int_copy_data_contents(kcontext,
                                      &authentication_indicators_attr,
                                      &attrs[i++]);
    if (code != 0)
        goto cleanup;

    attrs[i].data = NULL;
    attrs[i].length = 0;

    *out_attrs = attrs;
    attrs = NULL;

cleanup:
    if (attrs != NULL) {
        for (i = 0; attrs[i].data; i++)
            krb5_free_data_contents(kcontext, &attrs[i]);
        free(attrs);
    }

    return 0;
}

static krb5_error_code
authind_get_attribute(krb5_context kcontext,
                        krb5_authdata_context context,
                        void *plugin_context,
                        void *request_context,
                        const krb5_data *attribute,
                        krb5_boolean *authenticated,
                        krb5_boolean *complete,
                        krb5_data *value,
                        krb5_data *display_value,
                        int *more)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code code;
    krb5_data *indicator;
    int i;

    if (display_value != NULL) {
        display_value->data = NULL;
        display_value->length = 0;
    }

    if (!data_eq(*attribute, authentication_indicators_attr))
        return ENOENT;

    i = -(*more) - 1;
    if (i < 0)
        return EINVAL;
    else if (i >= aictx->count)
        return ENOENT;

    indicator = aictx->indicators[i];
    assert(indicator != NULL);

    code = krb5_copy_data(kcontext, indicator, &value);
    if (code != 0)
        return code;

    i++;

    if (i == aictx->count)
        *more = 0;
    else
        *more = -(i + 1);

    *authenticated = aictx->authenticated;
    *complete = TRUE;

    return 0;
}

static krb5_error_code
authind_set_attribute(krb5_context kcontext,
                        krb5_authdata_context context,
                        void *plugin_context,
                        void *request_context,
                        krb5_boolean complete,
                        const krb5_data *attribute,
                        const krb5_data *value)
{
    /* Only the KDC can set this attribute. */
    if (!data_eq(*attribute, authentication_indicator_attr))
        return ENOENT;

    return EPERM;
}

static krb5_error_code
authind_export_internal(krb5_context kcontext,
                          krb5_authdata_context context,
                          void *plugin_context,
                          void *request_context,
                          krb5_boolean restrict_authenticated,
                          void **ptr)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code code;
    int num;
    int i;
    krb5_data *indicators;

    *ptr = NULL;

    if (aictx->count == 0)
        return ENOENT;

    if (restrict_authenticated && aictx->authenticated != TRUE)
        return ENOENT;

    num = 0;
    indicators = k5calloc(aictx->count + 1, sizeof(krb5_data), &code);
    if (indicators == NULL)
        return code;

    for (i = 0; i < aictx->count; i++) {
        code = krb5int_copy_data_contents(kcontext, *aictx->indicators[i],
                                          &indicators[i]);
        if (code != 0)
            goto cleanup;
        num++;
    }

    indicators[i] = NULL;

    *ptr = indicators;
    indicators = NULL;
    num = 0;

cleanup:
    authind_free_indicators(kcontext, num, indicators);

    return code;
}

static krb5_error_code
authind_size(krb5_context kcontext,
               krb5_authdata_context context,
               void *plugin_context,
               void *request_context,
               size_t *sizep)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code code = 0;
    int i;

    *sizep += sizeof(krb5_int32); /* version */
    *sizep += sizeof(krb5_int32); /* authind count */

    for (i = 0; i < aictx->count; i++) {
        *sizep += sizeof(krb5_int32) + /* length */
                  (size_t)aictx->indicators[i]->length;
    }
    *sizep += sizeof(krb5_int32); /* authenticated flag */

    return code;
}

static krb5_error_code
authind_externalize(krb5_context kcontext,
                      krb5_authdata_context context,
                      void *plugin_context,
                      void *request_context,
                      krb5_octet **buffer,
                      size_t *lenremain)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code code = 0;
    size_t required = 0;
    krb5_octet *bp;
    size_t remain;
    int i = 0;

    bp = *buffer;
    remain = *lenremain;

    authind_size(kcontext, context, plugin_context,
                   request_context, &required);

    if (required > remain)
        return ENOMEM;

    krb5_ser_pack_int32(1, &bp, &remain); /* version */
    krb5_ser_pack_int32(aictx->count, &bp, &remain); /* authind count */

    for (i = 0; i < aictx->count; i++) {
        krb5_ser_pack_int32(aictx->indicators[i]->length, &bp, &remain);
        code = krb5_ser_pack_bytes(aictx->indicators[i]->data,
                                   (size_t)aictx->indicators[i]->length,
                                   &bp, &remain);
        if (code != 0)
            return code;
    }

    /* authenticated */
    krb5_ser_pack_int32(aictx->authenticated, &bp, &remain);

    *buffer = bp;
    *lenremain = remain;

    return 0;
}

static krb5_error_code
authind_internalize(krb5_context kcontext,
                      krb5_authdata_context context,
                      void *plugin_context,
                      void *request_context,
                      krb5_octet **buffer,
                      size_t *lenremain)
{
    struct authind_context *aictx = (struct authind_context *)request_context;
    krb5_error_code code;
    krb5_int32 ibuf;
    krb5_octet *bp;
    size_t remain;
    int count;
    krb5_data *indicators = NULL;

    bp = *buffer;
    remain = *lenremain;

    /* version */
    code = krb5_ser_unpack_int32(&ibuf, &bp, &remain);
    if (code != 0)
        goto cleanup;

    if (ibuf != 1) {
        code = EINVAL;
        goto cleanup;
    }

    /* count */
    code = krb5_ser_unpack_int32(&count, &bp, &remain);
    if (code != 0)
        goto cleanup;

    if (count > 65535) {
        return ERANGE; /* let's set some reasonable limits here */
    } else if (count > 0) {
        int i;

        indicators = k5calloc(count + 1, sizeof(krb5_data), &code);
        if (delegated == NULL)
            goto cleanup;

        for (i = 0; i < count; i++) {
            /* Get the length */
            (void)krb5_ser_unpack_int32(&ibuf, &bp, &remain);
            indicators[i].data = k5alloc(ibuf, &code);
            if (code != 0)
                goto cleanup;

            code = krb5_ser_unpack_bytes(indicators[i].data,
                                         (size_t)ibuf, &bp, &remain);
            if (code != 0)
                goto cleanup;
            indicators[i].length = ibuf;
            indicators[i].magic = KV5M_DATA;
        }

        indicators[i] = NULL;
    }

    code = krb5_ser_unpack_int32(&ibuf, &bp, &remain);
    if (code != 0)
        goto cleanup;

    authind_free_indicators(kcontext, aictx->count, aictx->indicators);

    aictx->count = count;
    aictx->indicators = indicators;
    aictx->authenticated = (ibuf != 0);

    indicators = NULL;

    *buffer = bp;
    *lenremain = remain;

cleanup:
    authind_free_indicators(kcontext, num, indicators);

    return code;
}

static krb5_error_code
authind_copy(krb5_context kcontext,
               krb5_authdata_context context,
               void *plugin_context,
               void *request_context,
               void *dst_plugin_context,
               void *dst_req_context)
{
    struct authind_context *srcctx = (struct authind_context *)request_context;
    struct authind_context *dstctx = (struct authind_context *)dst_req_context;
    krb5_error_code code;

    code = authind_export_internal(kcontext, context,
                                     plugin_context, request_context,
                                     FALSE, (void **)&dstctx->indicators);
    if (code != 0 && code != ENOENT)
        return code;

    dstctx->count = srcctx->count;
    dstctx->authenticated = srcctx->authenticated;

    return 0;
}

static krb5_authdatatype authind_ad_types[] = {
    KRB5_AUTHDATA_AUTH_INDICATOR, 0
};

krb5plugin_authdata_client_ftable_v0 krb5int_authind_authdata_client_ftable = {
    "authentication-indicators",
    authind_ad_types,
    authind_init,
    authind_fini,
    authind_flags,
    authind_request_init,
    authind_request_fini,
    authind_get_attribute_types,
    authind_get_attribute,
    authind_set_attribute,
    NULL, /* delete_attribute_proc */
    authind_export_authdata,
    authind_import_authdata,
    authind_export_internal,
    authind_free_internal,
    authind_verify,
    authind_size,
    authind_externalize,
    authind_internalize,
    authind_copy
};
