/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.java.otr4j.context.*;

/**
 * 
 * @author George Politis
 *
 */
public final class UserState {
	private static Logger logger = Logger
			.getLogger(ConnContext.class.getName());

	private Vector<ConnContext> contextPool = new Vector<ConnContext>();

	private ConnContext getConnContext(String user, String account,
			String protocol) {

		if (Utils.IsNullOrEmpty(user) || Utils.IsNullOrEmpty(account)
				|| Utils.IsNullOrEmpty(protocol)) {
			throw new IllegalArgumentException();
		}

		for (ConnContext connContext : contextPool) {
			if (connContext.getAccount().equals(account)
					&& connContext.getUser().equals(user)
					&& connContext.getProtocol().equals(protocol)) {
				return connContext;
			}
		}

		ConnContext context = new ConnContext(user, account, protocol);
		contextPool.add(context);

		return context;
	}

	public String handleReceivingMessage(OTR4jListener listener, String user,
			String account, String protocol, String msgText) throws Exception {

		ConnContext ctx = this.getConnContext(user, account, protocol);
		try {
			return ctx.handleReceivingMessage(msgText, listener);
		} catch (Exception e) {
			logger
					.log(
							Level.SEVERE,
							"Handling message receiving failed, returning original message.",
							e);
			return msgText;
		}
	}

	public String handleSendingMessage(OTR4jListener listener, String user,
			String account, String protocol, String msgText) {
		
		ConnContext ctx = this.getConnContext(user, account, protocol);
		try {
			return ctx.handleSendingMessage(msgText);
		} catch (Exception e) {
			logger
					.log(
							Level.SEVERE,
							"Handling message sending failed, returning original message.",
							e);
			return msgText;
		}
	}
}
