package net.java.otr4j;

import java.util.*;
import net.java.otr4j.context.*;

public final class UserState {

    private Vector<ConnContext> contextPool = new Vector<ConnContext>();

    public ConnContext getConnContext(String user, String account, String protocol) {

        if (Utils.IsNullOrEmpty(user) || Utils.IsNullOrEmpty(account) || Utils.IsNullOrEmpty(protocol)) {
            throw new IllegalArgumentException();
        }

        for (ConnContext connContext : contextPool) {
            if (connContext.account.equals(account) && connContext.user.equals(user) && connContext.protocol.equals(protocol)) {
                return connContext;
            }
        }

        ConnContext context = new ConnContext(user, account, protocol);
        contextPool.add(context);

        return context;
    }
}
