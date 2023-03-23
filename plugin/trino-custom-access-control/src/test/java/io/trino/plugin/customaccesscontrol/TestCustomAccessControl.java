/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.plugin.customaccesscontrol;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import io.trino.security.AccessControlConfig;
import io.trino.security.AccessControlManager;
import io.trino.security.SecurityContext;
import io.trino.spi.QueryId;
import io.trino.spi.security.Identity;
import io.trino.transaction.TransactionManager;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.Set;

import static io.trino.testing.TestingEventListenerManager.emptyEventListenerManager;
import static io.trino.transaction.InMemoryTransactionManager.createTestTransactionManager;
import static io.trino.transaction.TransactionBuilder.transaction;
import static org.testng.Assert.assertEquals;

public class TestCustomAccessControl
{
    private static final Identity admin = Identity.forUser("alberto").withEnabledRoles(ImmutableSet.of("admin")).build();
    private static final QueryId queryId = new QueryId("query_id");
    private static final Set<String> allCatalogs = ImmutableSet.of("secret", "open-to-all", "all-allowed", "alice-catalog", "\u0200\u0200\u0200", "staff-catalog");

    @BeforeClass
    public void setUp()
    {
        System.setProperty("io.trino.testng.services.FlakyTestRetryAnalyzer.enabled", "true");
    }

    @Test
    public void testCatalogOperations()
    {
        TransactionManager transactionManager = createTestTransactionManager();
        AccessControlManager accessControlManager = newAccessControlManager(transactionManager, "http://192.168.31.137:8000/check_access");

        transaction(transactionManager, accessControlManager)
                .execute(transactionId -> {
                    assertEquals(accessControlManager.filterCatalogs(new SecurityContext(transactionId, admin, queryId), allCatalogs), allCatalogs);
                });
    }

    @Test
    public void testCatalogOperationsReadOnly()
    {
        TransactionManager transactionManager = createTestTransactionManager();
        AccessControlManager accessControlManager = newAccessControlManager(transactionManager, "http://192.168.31.137:8000/get_rules");

        transaction(transactionManager, accessControlManager)
                .execute(transactionId -> {
                    assertEquals(accessControlManager.filterCatalogs(new SecurityContext(transactionId, admin, queryId), allCatalogs), allCatalogs);
                });
    }

    private AccessControlManager newAccessControlManager(TransactionManager transactionManager, String url)
    {
        AccessControlManager accessControlManager = new AccessControlManager(transactionManager, emptyEventListenerManager(), new AccessControlConfig(), CustomAccessControl.NAME);
        accessControlManager.addSystemAccessControlFactory(new CustomAccessControl.Factory());
        accessControlManager.loadSystemAccessControl(CustomAccessControl.NAME, ImmutableMap.of("security.opa-server-url", url));

        return accessControlManager;
    }
}
