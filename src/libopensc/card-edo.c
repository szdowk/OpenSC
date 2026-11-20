/*
 * Copyright (C) 2020 Piotr Majkrzak
 *
 * This file is part of OpenSC.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(ENABLE_SM) && defined(ENABLE_OPENPACE)

#include "libopensc/internal.h"
#include "libopensc/opensc.h"
#include "libopensc/sm.h"
#include "libopensc/asn1.h"
#include "sm/sm-eac.h"
#include <string.h>
#include <stdlib.h>
#include "card-edo-pinentry.h"
#include "card-edo-can-store.h"


struct edo_private {
	char can[7];
	/* Only an available CAN may trigger a manual recovery prompt. */
	int entered;
	int save_ask;
	int storage_allowed;
	int save_offered;
};


static struct sc_card_operations edo_ops;


static struct sc_card_driver edo_drv = {
	"Polish eID card (e-dowód, eDO)",
	"edo",
	&edo_ops,
	NULL, 0, NULL
};


static const struct sc_atr_table edo_atrs[] = {
	{ "3b:89:80:01:02:4d:4b:4d:57:4b:53:4b:54:11", NULL, NULL, SC_CARD_TYPE_EDO_MK, 0, NULL },
	{ "3b:84:80:01:47:43:50:43:12", NULL, NULL, SC_CARD_TYPE_EDO, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};


static int edo_is_mk(const struct sc_card *card) {
	return card->type == SC_CARD_TYPE_EDO_MK;
}


static struct {
	int len;
	struct sc_object_id oid;
} edo_curves[] = {
	// secp384r1
	{384, {{1, 3, 132, 0, 34, -1}}}
};


static int edo_match_card(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (_sc_match_atr(card, edo_atrs, &card->type) >= 0) {
		sc_log(card->ctx, "ATR recognized as Polish eID card.");
		LOG_FUNC_RETURN(card->ctx, 1);
	}
	LOG_FUNC_RETURN(card->ctx, 0);
}


static int edo_get_configured_can(sc_card_t* card, struct sc_establish_pace_channel_input* pace_input) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	const char* can;

	can = getenv("EDO_CAN");

	/* A nonempty environment value overrides the configured CAN. */
	if (!can || can[0] == '\0') {
		for (size_t i = 0; card->ctx->conf_blocks[i]; ++i) {
			scconf_block** blocks = scconf_find_blocks(card->ctx->conf, card->ctx->conf_blocks[i], "card_driver", "edo");
			if (!blocks)
				continue;
			for (size_t j = 0; blocks[j]; ++j)
				if ((can = scconf_get_str(blocks[j], "can", NULL)))
					break;
			free(blocks);
		}
	}

	if (!can || 6 != strlen(can)) {
		sc_log(card->ctx, "Missing or invalid CAN. 6 digits required.");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	pace_input->pin_id = SC_PACE_PIN_ID_CAN;
	pace_input->pin = (const unsigned char*)can;
	pace_input->pin_length = 6;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static const char *edo_can_prompt_mode(sc_card_t *card)
{
	const char *mode = "always";
	size_t i, j;

	for (i = 0; card->ctx->conf_blocks[i]; ++i) {
		scconf_block **blocks = scconf_find_blocks(card->ctx->conf,
			card->ctx->conf_blocks[i], "card_driver", "edo");
		if (!blocks)
			continue;
		for (j = 0; blocks[j]; ++j)
			mode = scconf_get_str(blocks[j], "can_prompt", mode);
		free(blocks);
	}
	return mode;
}

static int edo_can_valid(const unsigned char *can, size_t length)
{
	size_t i;

	if (!can || length != 6)
		return 0;
	for (i = 0; i < length; ++i)
		if (can[i] < '0' || can[i] > '9')
			return 0;
	return 1;
}

static int edo_can_storage_policy(sc_card_t *card,
		int *ask, int *allowed)
{
	const char *save = "no";
	size_t i, j;

	*ask = 0;
	*allowed = 1;
	for (i = 0; card->ctx->conf_blocks[i]; ++i) {
		scconf_block **blocks = scconf_find_blocks(card->ctx->conf,
			card->ctx->conf_blocks[i], "card_driver", "edo");
		if (!blocks)
			continue;
		for (j = 0; blocks[j]; ++j) {
			const char *permission = scconf_get_str(blocks[j],
				"can_save_allowed", NULL);
			save = scconf_get_str(blocks[j], "can_save", save);
			if (permission) {
				/* A later block cannot undo an applicable storage prohibition. */
				if (!strcmp(permission, "no"))
					*allowed = 0;
				else if (strcmp(permission, "yes")) {
					free(blocks);
					return SC_ERROR_INVALID_ARGUMENTS;
				}
			}
		}
		free(blocks);
	}
	if (strcmp(save, "no") && strcmp(save, "ask"))
		return SC_ERROR_INVALID_ARGUMENTS;
	*ask = *allowed && !strcmp(save, "ask");
	return SC_SUCCESS;
}

static int edo_load_available_can(sc_card_t *card,
		int storage_allowed, char can[7])
{
	struct sc_establish_pace_channel_input configured;
	int r;

	sc_mem_clear(can, 7);
	memset(&configured, 0, sizeof(configured));
	r = edo_get_configured_can(card, &configured);
	if (r == SC_SUCCESS &&
			edo_can_valid(configured.pin, configured.pin_length)) {
		memcpy(can, configured.pin, 6);
		return SC_SUCCESS;
	}
	if (storage_allowed)
		return edo_can_store_read(can);
	return SC_ERROR_OBJECT_NOT_FOUND;
}

static int edo_prepare_can(sc_card_t *card, struct edo_private *priv)
{
	const char *mode = edo_can_prompt_mode(card);
	char available[7] = {0};
	int r;

	if (strcmp(mode, "always") && strcmp(mode, "never")
			&& strcmp(mode, "confirm")) {
		sc_log(card->ctx, "Invalid edo can_prompt setting.");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	r = edo_can_storage_policy(card, &priv->save_ask,
		&priv->storage_allowed);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "Invalid edo CAN storage policy.");
		return r;
	}

	/* A connection-local decision is independent of persistent storage. */
	if (edo_can_valid((const unsigned char *)priv->can, 6))
		return SC_SUCCESS;
	sc_mem_clear(priv->can, sizeof(priv->can));
	priv->entered = 0;
	priv->save_offered = 0;

	if (strcmp(mode, "always")) {
		r = edo_load_available_can(card, priv->storage_allowed, available);
		if (r == SC_SUCCESS) {
			if (!strcmp(mode, "never")) {
				memcpy(priv->can, available, sizeof(priv->can));
				goto done;
			}
			r = edo_pinentry_request(card,
				"Czy użyć dostępnego CAN z dowodu osobistego?",
				"Użyj zapisanego", "Wpisz inny", NULL);
			if (r == SC_SUCCESS) {
				memcpy(priv->can, available, sizeof(priv->can));
				goto done;
			}
			if (r != SC_ERROR_NOT_ALLOWED)
				goto done;
		}
	}

	r = edo_pinentry_request(card,
		"Wpisz 6-cyfrowy CAN z dowodu osobistego. "
		"CAN jest numerem nadrukowanym na dokumencie, "
		"a nie kodem PIN1 ani PIN2.",
		"Dalej", NULL, priv->can);
	if (r == SC_SUCCESS)
		priv->entered = 1;

done:
	sc_mem_clear(available, sizeof(available));
	return r;
}

/* Ask only after successful PACE; declining must not fail that connection. */
static void edo_offer_can_save(sc_card_t *card, struct edo_private *priv)
{
	int r;

	if (!priv->entered || !priv->save_ask || !priv->storage_allowed
			|| priv->save_offered)
		return;
	priv->save_offered = 1;
	r = edo_pinentry_request(card,
		"CAN został poprawnie użyty do połączenia z dowodem. "
		"Czy zapisać go dla tego konta użytkownika? "
		"Wybierz Anuluj, aby użyć go tylko w bieżącym połączeniu.",
		"Zapisz", NULL, NULL);
	if (r != SC_SUCCESS)
		return;
	r = edo_can_store_write(priv->can);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "Could not persist CAN.");
		(void)edo_pinentry_request(card,
			"Nie udało się zapisać CAN. "
			"Będzie dostępny tylko w bieżącym połączeniu.",
			"Dalej", NULL, NULL);
	}
}

static int edo_pace_once(sc_card_t *card, const char can[7])
{
	struct sc_establish_pace_channel_input input;

	memset(&input, 0, sizeof(input));
	input.pin_id = SC_PACE_PIN_ID_CAN;
	input.pin = (const unsigned char *)can;
	input.pin_length = 6;

	return perform_pace(card, input, NULL, EAC_TR_VERSION_2_02);
}

static int edo_can_offer_recovery(sc_card_t *card,
		const struct edo_private *priv, int result)
{
	if (priv->entered ||
			(card->ctx->flags & SC_CTX_FLAG_DISABLE_POPUPS))
		return 0;

	/*
	 * These errors can include an unsuitable CAN, but do not prove it.
	 * Only offer manual input; never retry an available CAN automatically.
	 */
	switch (result) {
	case SC_ERROR_PIN_CODE_INCORRECT:
	case SC_ERROR_SECURITY_STATUS_NOT_SATISFIED:
	case SC_ERROR_CARD_CMD_FAILED:
	case SC_ERROR_INTERNAL:
		return 1;
	default:
		return 0;
	}
}

static int edo_unlock(sc_card_t *card)
{
	struct edo_private *priv = card->drv_data;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (!priv)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	r = edo_prepare_can(card, priv);
	if (r != SC_SUCCESS) {
		sc_mem_clear(priv->can, sizeof(priv->can));
		LOG_FUNC_RETURN(card->ctx, r);
	}

	r = edo_pace_once(card, priv->can);
	if (r != SC_SUCCESS && edo_can_offer_recovery(card, priv, r)) {
		sc_mem_clear(priv->can, sizeof(priv->can));
		r = edo_pinentry_request(card,
			"Nie udało się połączyć z dowodem przy użyciu "
			"dostępnego CAN. Możesz wpisać CAN nadrukowany "
			"na przyłożonym dowodzie i spróbować ponownie "
			"albo wybrać Anuluj.",
			"Połącz", NULL, priv->can);
		if (r == SC_SUCCESS) {
			priv->entered = 1;
			priv->save_offered = 0;
			r = sc_sm_stop(card);
			if (r == SC_SUCCESS)
				r = edo_pace_once(card, priv->can);
		}
	}
	if (r != SC_SUCCESS) {
		sc_mem_clear(priv->can, sizeof(priv->can));
		sc_log(card->ctx, "Error establishing PACE with CAN.");
	} else {
		edo_offer_can_save(card, priv);
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

static int edo_finish(sc_card_t *card)
{
	struct edo_private *priv = card->drv_data;

	if (priv) {
		sc_mem_clear(priv, sizeof(*priv));
		free(priv);
		card->drv_data = NULL;
	}
	return SC_SUCCESS;
}


struct edo_buff {
	u8 val[SC_MAX_APDU_RESP_SIZE];
	size_t len;
};


static int edo_select_mf(struct sc_card* card, struct edo_buff* buff) {
	LOG_FUNC_CALLED(card->ctx);
	struct sc_apdu apdu;
	sc_format_apdu_ex(&apdu, 00, 0xA4, 0x00, 0x00, NULL, 0, buff->val, sizeof buff->val);
	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "SW check failed");
	buff->len = apdu.resplen;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int edo_select_df(struct sc_card* card, const u8 path[2], struct edo_buff* buff) {
	LOG_FUNC_CALLED(card->ctx);
	struct sc_apdu apdu;
	sc_format_apdu_ex(&apdu, 00, 0xA4, 0x01, 0x04, path, 2, buff->val, sizeof buff->val);
	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "SW check failed");
	buff->len = apdu.resplen;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int edo_select_ef(struct sc_card* card, const u8 path[2], struct edo_buff* buff) {
	LOG_FUNC_CALLED(card->ctx);
	struct sc_apdu apdu;
	/* MK requests its FCI with P2=00; retain P2=04 for legacy cards. */
	sc_format_apdu_ex(&apdu, 00, 0xA4, 0x02, edo_is_mk(card) ? 0x00 : 0x04, path, 2, buff->val, sizeof buff->val);
	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "SW check failed");
	buff->len = apdu.resplen;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int edo_select_name(struct sc_card* card, const u8* name, size_t namelen, struct edo_buff* buff) {
	LOG_FUNC_CALLED(card->ctx);
	buff->len = sizeof buff->val;
	LOG_FUNC_RETURN(card->ctx, iso7816_select_aid(card, name, namelen, buff->val, &buff->len));
}


static int edo_select_path(struct sc_card* card, const u8* path, size_t pathlen, struct edo_buff* buff) {
	LOG_FUNC_CALLED(card->ctx);
	while (pathlen >= 2) {
		if (path[0] == 0x3F && path[1]  == 0x00)
			LOG_TEST_RET(card->ctx, edo_select_mf(card, buff), "MF select failed");
		else if ((edo_is_mk(card) && pathlen > 2) || path[0] == 0xDF)
			LOG_TEST_RET(card->ctx, edo_select_df(card, path, buff), "DF select failed");
		else if (pathlen == 2)
			LOG_TEST_RET(card->ctx, edo_select_ef(card, path, buff), "EF select failed");
		else
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

		path += 2;
		pathlen -= 2;
	}
	if (pathlen)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/*! Selects file specified by given path.
 *
 * Card does not support selecting file at once, that's why it have to be done in following way:
 * 1. Select AID if provided,
 * 2. Select MF if provided,
 * 3. Select DF until provided,
 * 4. Select EF if provided.
 */
static int edo_select_file(struct sc_card* card, const struct sc_path* in_path, struct sc_file** file_out) {
	LOG_FUNC_CALLED(card->ctx);
	struct edo_buff buff = {0};

	switch (in_path->type) {
		case SC_PATH_TYPE_PATH:
		case SC_PATH_TYPE_FILE_ID:
			if (in_path->aid.len)
				LOG_TEST_RET(card->ctx, edo_select_name(card, in_path->aid.value, in_path->aid.len, &buff), "Select AID failed");
			if (in_path->len)
				LOG_TEST_RET(card->ctx, edo_select_path(card, in_path->value, in_path->len, &buff), "Select path failed");
			break;
		case SC_PATH_TYPE_DF_NAME:
			LOG_TEST_RET(card->ctx, edo_select_name(card, in_path->value, in_path->len, &buff), "Select AID failed");
			break;
		default:
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}

	if (file_out) {
		if (buff.len < 2)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		if (!(*file_out = sc_file_new()))
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
		(*file_out)->path = *in_path;
		LOG_TEST_RET(card->ctx, card->ops->process_fci(card, *file_out, buff.val, buff.len), "Process FCI failed");
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/*! Computes ECDSA signature.
 *
 * Legacy cards return DER; the MK ATR variant returns fixed-width R || S.
 * Both paths return the signature length required by PKCS#11.
 */
static int edo_compute_signature(struct sc_card* card, const u8* data, size_t datalen, u8* out, size_t outlen) {
	LOG_FUNC_CALLED(card->ctx);
	u8 sig[SC_MAX_APDU_RESP_SIZE];
	u8 padded_digest[48];
	int r;

	/* MK returns raw bytes, so it bypasses the DER decoder validation. */
	if (edo_is_mk(card)) {
		if (!out)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
		if (outlen < 96)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);
	}

	/* This card variant requires a full-width P-384 input.
	 * Left zero padding preserves the ECDSA digest integer. */
	if (edo_is_mk(card) && datalen < sizeof padded_digest) {
		if (!data || !datalen)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
		memset(padded_digest, 0, sizeof padded_digest);
		memcpy(padded_digest + sizeof padded_digest - datalen, data, datalen);
		data = padded_digest;
		datalen = sizeof padded_digest;
	}

	r = sc_get_iso7816_driver()->ops->compute_signature(
			card, data, datalen, sig, sizeof sig);
	LOG_TEST_RET(card->ctx, r, "Internal signature failed");

	/* This ATR variant returns fixed-width r || s; legacy cards return DER. */
	if (edo_is_mk(card)) {
		if (r != 96)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_DATA);
		memcpy(out, sig, 96);
		LOG_FUNC_RETURN(card->ctx, 96);
	}

	/* The edo driver currently supports secp384r1 only. */
	r = sc_asn1_decode_ecdsa_signature(
			card->ctx, sig, (size_t)r, edo_curves[0].len / 8, &out, outlen);
	LOG_FUNC_RETURN(card->ctx, r);
}


/*! Sets security environment
 *
 * Card expects key file to be selected first, followed by the
 * set security env packet with: 0x80, 0x01, 0xcc, 0x84, 0x01, 0x80|x,
 * where x is the key reference byte.
 */
static int edo_set_security_env(struct sc_card* card, const struct sc_security_env* env, int se_num) {
	LOG_FUNC_CALLED(card->ctx);
	struct sc_apdu apdu;
	/* Both payloads must outlive formatting and remain valid until transmit. */
	u8 legacy_payload[] = {0x80, 0x01, 0xcc, 0x84, 0x01, 0x00};
	u8 mk_payload[] = {0x91, 0x02, 0x22, 0x00};

	if (env->algorithm != SC_ALGORITHM_EC ||
	    env->operation != SC_SEC_OPERATION_SIGN ||
	    !(env->flags & SC_SEC_ENV_KEY_REF_PRESENT))
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	if (edo_is_mk(card)) {
		mk_payload[3] = 0x80 | env->key_ref[0];
		/* The PKCS#15 layer has already selected the full key path. */
		sc_format_apdu_ex(&apdu, 0x00, 0x22, 0x81, 0xB6,
			mk_payload, sizeof mk_payload, NULL, 0);
	} else {
		legacy_payload[5] = 0x80 | env->key_ref[0];
		/* Preserve the original legacy card protocol. */
		sc_format_apdu_ex(&apdu, 0x00, 0x22, 0x41, 0xB6,
			legacy_payload, sizeof legacy_payload, NULL, 0);
		LOG_TEST_RET(card->ctx, sc_select_file(card, &env->file_ref, NULL), "SELECT file failed");
	}

	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "SW check failed");
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/*! Initializes card driver.
 *
 * Card is known to support only short APDU-s.
 * Preinitialized keys are on secp384r1 curve.
 * PACE channel have to be established.
 */
static int edo_init(sc_card_t* card) {
	int r;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	memset(&card->sm_ctx, 0, sizeof card->sm_ctx);

	card->max_send_size = SC_MAX_APDU_RESP_SIZE;
	card->max_recv_size = SC_MAX_APDU_RESP_SIZE;

	for (size_t i = 0; i < sizeof edo_curves / sizeof * edo_curves; ++i) {
		LOG_TEST_RET(card->ctx, _sc_card_add_ec_alg(
			card, edo_curves[i].len,
			SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDSA_HASH_NONE,
			0, &edo_curves[i].oid
		), "Add EC alg failed");
	}

	LOG_TEST_RET(card->ctx, sc_enum_apps(card), "Enumerate apps failed");

	card->drv_data = calloc(1, sizeof(struct edo_private));
	if (!card->drv_data)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	r = edo_unlock(card);
	if (r != SC_SUCCESS) {
		edo_finish(card);
		LOG_FUNC_RETURN(card->ctx, r);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int edo_logout(sc_card_t* card) {
	sc_sm_stop(card);
	return edo_unlock(card);
}


struct sc_card_driver* sc_get_edo_driver(void) {
	edo_ops = *sc_get_iso7816_driver()->ops;
	edo_ops.match_card = edo_match_card;
	edo_ops.init = edo_init;
	edo_ops.finish = edo_finish;
	edo_ops.select_file = edo_select_file;
	edo_ops.set_security_env = edo_set_security_env;
	edo_ops.compute_signature = edo_compute_signature;
	edo_ops.logout = edo_logout;

	return &edo_drv;
}

#else

#include "libopensc/opensc.h"

struct sc_card_driver* sc_get_edo_driver(void) {
	return NULL;
}

#endif
