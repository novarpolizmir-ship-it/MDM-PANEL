/*
 *
 * Headwind MDM: Open Source Android MDM Software
 * https://h-mdm.com
 *
 * Copyright (C) 2019 Headwind Solutions LLC (http://h-sms.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.hmdm.rest.resource;

import com.google.common.io.BaseEncoding;
import com.hmdm.persistence.CommonDAO;
import com.hmdm.persistence.UnsecureDAO;
import com.hmdm.persistence.UserDAO;
import com.hmdm.persistence.domain.Settings;
import com.hmdm.persistence.domain.User;
import com.hmdm.rest.filter.AuthFilter;
import com.hmdm.rest.json.Response;
import com.hmdm.security.SecurityContext;
import net.glxn.qrgen.core.image.ImageType;
import net.glxn.qrgen.javase.QRCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.StreamingOutput;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

@Singleton
@Path("/private/twofactor")
public class TwoFactorAuthResource {

    private static final Logger logger = LoggerFactory.getLogger(TwoFactorAuthResource.class);
    private static final String HMAC_SHA1 = "HmacSHA1";
    private static final int SECRET_SIZE = 20;
    private static final int CODE_DIGITS = 6;
    private static final int TIME_STEP_SECONDS = 30;
    private static final int ALLOWED_TIME_DRIFT = 1;

    private UserDAO userDAO;
    private UnsecureDAO unsecureDAO;
    private CommonDAO commonDAO;

    public TwoFactorAuthResource() {
    }

    @Inject
    public TwoFactorAuthResource(UserDAO userDAO, UnsecureDAO unsecureDAO, CommonDAO commonDAO) {
        this.userDAO = userDAO;
        this.unsecureDAO = unsecureDAO;
        this.commonDAO = commonDAO;
    }

    @GET
    @Path("/qr/{userId}")
    @Produces("image/png")
    public javax.ws.rs.core.Response getQrCode(@PathParam("userId") int userId) {
        try {
            User currentUser = SecurityContext.get().getCurrentUser()
                    .orElse(null);
            if (currentUser == null || currentUser.getId() != userId) {
                return javax.ws.rs.core.Response.status(403).build();
            }

            User dbUser = userDAO.getUserDetails(userId);
            String secret = dbUser.getTwoFactorSecret();
            if (secret == null || secret.isEmpty()) {
                secret = generateSecret();
                dbUser.setTwoFactorSecret(secret);
                dbUser.setTwoFactorAccepted(false);
                dbUser.setNewPassword(dbUser.getPassword());
                unsecureDAO.updateUserUnsecure(dbUser);
            }

            String otpAuthUrl = buildOtpAuthUrl(secret, dbUser.getLogin());

            ByteArrayOutputStream qrStream = QRCode.from(otpAuthUrl)
                    .to(ImageType.PNG)
                    .withSize(250, 250)
                    .stream();

            byte[] qrBytes = qrStream.toByteArray();
            return javax.ws.rs.core.Response.ok(qrBytes, "image/png").build();

        } catch (Exception e) {
            logger.error("Error generating 2FA QR code", e);
            return javax.ws.rs.core.Response.serverError().build();
        }
    }

    @GET
    @Path("/verify/{user}/{code}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response verify(@PathParam("user") int userId,
                           @PathParam("code") String code,
                           @Context HttpServletRequest req) {
        try {
            User currentUser = SecurityContext.get().getCurrentUser()
                    .orElse(null);
            if (currentUser == null || currentUser.getId() != userId) {
                return Response.ERROR("error.permission.denied");
            }

            User dbUser = userDAO.getUserDetails(userId);
            String secret = dbUser.getTwoFactorSecret();
            if (secret == null || secret.isEmpty()) {
                return Response.ERROR("error.permission.denied");
            }

            int codeInt;
            try {
                codeInt = Integer.parseInt(code);
            } catch (NumberFormatException e) {
                return Response.ERROR("error.permission.denied");
            }

            if (!verifyTotp(secret, codeInt)) {
                return Response.ERROR("error.permission.denied");
            }

            if (!dbUser.isTwoFactorAccepted()) {
                dbUser.setTwoFactorAccepted(true);
                dbUser.setNewPassword(dbUser.getPassword());
                unsecureDAO.updateUserUnsecure(dbUser);
            }

            HttpSession session = req.getSession(false);
            if (session != null && session.getAttribute(AuthFilter.twoFactorNeeded) != null) {
                session.removeAttribute(AuthFilter.twoFactorNeeded);
            }

            return Response.OK();

        } catch (Exception e) {
            logger.error("Error verifying 2FA code", e);
            return Response.INTERNAL_ERROR();
        }
    }

    @GET
    @Path("/set")
    @Produces(MediaType.APPLICATION_JSON)
    public Response enable() {
        try {
            User currentUser = SecurityContext.get().getCurrentUser()
                    .orElse(null);
            if (currentUser == null) {
                return Response.ERROR("error.permission.denied");
            }

            Settings settings = commonDAO.getSettings();
            if (settings == null) {
                settings = new Settings();
            }
            settings.setTwoFactor(true);
            commonDAO.setTwoFactor(settings);

            return Response.OK();

        } catch (Exception e) {
            logger.error("Error enabling 2FA", e);
            return Response.INTERNAL_ERROR();
        }
    }

    @GET
    @Path("/reset")
    @Produces(MediaType.APPLICATION_JSON)
    public Response reset() {
        try {
            User currentUser = SecurityContext.get().getCurrentUser()
                    .orElse(null);
            if (currentUser == null) {
                return Response.ERROR("error.permission.denied");
            }

            User dbUser = userDAO.getUserDetails(currentUser.getId());
            dbUser.setTwoFactorSecret(null);
            dbUser.setTwoFactorAccepted(false);
            dbUser.setNewPassword(dbUser.getPassword());
            unsecureDAO.updateUserUnsecure(dbUser);

            Settings settings = commonDAO.getSettings();
            if (settings != null) {
                settings.setTwoFactor(false);
                commonDAO.setTwoFactor(settings);
            }

            return Response.OK();

        } catch (Exception e) {
            logger.error("Error resetting 2FA", e);
            return Response.INTERNAL_ERROR();
        }
    }

    private String generateSecret() {
        SecureRandom random = new SecureRandom();
        byte[] secretBytes = new byte[SECRET_SIZE];
        random.nextBytes(secretBytes);
        return BaseEncoding.base32().omitPadding().encode(secretBytes);
    }

    private String buildOtpAuthUrl(String secret, String username) {
        return "otpauth://totp/HeadwindMDM:" + username
                + "?secret=" + secret
                + "&issuer=HeadwindMDM"
                + "&algorithm=SHA1"
                + "&digits=" + CODE_DIGITS
                + "&period=" + TIME_STEP_SECONDS;
    }

    private boolean verifyTotp(String secret, int code) {
        long currentTimeStep = System.currentTimeMillis() / 1000 / TIME_STEP_SECONDS;
        for (int i = -ALLOWED_TIME_DRIFT; i <= ALLOWED_TIME_DRIFT; i++) {
            int generatedCode = generateTotp(secret, currentTimeStep + i);
            if (generatedCode == code) {
                return true;
            }
        }
        return false;
    }

    private int generateTotp(String secret, long timeStep) {
        try {
            byte[] secretBytes = BaseEncoding.base32().omitPadding().decode(secret);
            byte[] timeBytes = ByteBuffer.allocate(8).putLong(timeStep).array();

            Mac mac = Mac.getInstance(HMAC_SHA1);
            mac.init(new SecretKeySpec(secretBytes, HMAC_SHA1));
            byte[] hash = mac.doFinal(timeBytes);

            int offset = hash[hash.length - 1] & 0x0F;
            int truncated = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int modulo = (int) Math.pow(10, CODE_DIGITS);
            return truncated % modulo;

        } catch (Exception e) {
            logger.error("Error generating TOTP", e);
            return -1;
        }
    }
}
