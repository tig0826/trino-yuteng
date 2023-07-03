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
package io.trino.plugin.forepaasaccesscontrol;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import io.airlift.log.Logger;
import io.trino.plugin.base.security.CatalogAccessControlRule;
import io.trino.plugin.base.security.TableAccessControlRule;
import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.connector.CatalogSchemaRoutineName;
import io.trino.spi.connector.CatalogSchemaTableName;
import io.trino.spi.connector.SchemaTableName;
import io.trino.spi.function.FunctionKind;
import io.trino.spi.security.Identity;
import io.trino.spi.security.Privilege;
import io.trino.spi.security.SystemAccessControl;
import io.trino.spi.security.SystemAccessControlFactory;
import io.trino.spi.security.SystemSecurityContext;
import io.trino.spi.security.TrinoPrincipal;
import io.trino.spi.security.ViewExpression;
import io.trino.spi.type.Type;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.google.common.base.Preconditions.checkState;
import static com.google.common.base.Strings.isNullOrEmpty;
import static io.airlift.configuration.ConfigurationLoader.loadPropertiesFrom;
import static io.trino.plugin.base.security.CatalogAccessControlRule.AccessMode.ALL;
import static io.trino.plugin.base.security.CatalogAccessControlRule.AccessMode.READ_ONLY;
import static io.trino.plugin.base.security.TableAccessControlRule.TablePrivilege.DELETE;
import static io.trino.plugin.base.security.TableAccessControlRule.TablePrivilege.GRANT_SELECT;
import static io.trino.plugin.base.security.TableAccessControlRule.TablePrivilege.INSERT;
import static io.trino.plugin.base.security.TableAccessControlRule.TablePrivilege.OWNERSHIP;
import static io.trino.plugin.base.security.TableAccessControlRule.TablePrivilege.SELECT;
import static io.trino.plugin.base.security.TableAccessControlRule.TablePrivilege.UPDATE;
import static io.trino.spi.security.AccessDeniedException.denyAddColumn;
import static io.trino.spi.security.AccessDeniedException.denyAlterColumn;
import static io.trino.spi.security.AccessDeniedException.denyCatalogAccess;
import static io.trino.spi.security.AccessDeniedException.denyCommentColumn;
import static io.trino.spi.security.AccessDeniedException.denyCommentTable;
import static io.trino.spi.security.AccessDeniedException.denyCommentView;
import static io.trino.spi.security.AccessDeniedException.denyCreateCatalog;
import static io.trino.spi.security.AccessDeniedException.denyCreateMaterializedView;
import static io.trino.spi.security.AccessDeniedException.denyCreateRole;
import static io.trino.spi.security.AccessDeniedException.denyCreateTable;
import static io.trino.spi.security.AccessDeniedException.denyCreateView;
import static io.trino.spi.security.AccessDeniedException.denyCreateViewWithSelect;
import static io.trino.spi.security.AccessDeniedException.denyDeleteTable;
import static io.trino.spi.security.AccessDeniedException.denyDenyTablePrivilege;
import static io.trino.spi.security.AccessDeniedException.denyDropCatalog;
import static io.trino.spi.security.AccessDeniedException.denyDropColumn;
import static io.trino.spi.security.AccessDeniedException.denyDropMaterializedView;
import static io.trino.spi.security.AccessDeniedException.denyDropRole;
import static io.trino.spi.security.AccessDeniedException.denyDropTable;
import static io.trino.spi.security.AccessDeniedException.denyDropView;
import static io.trino.spi.security.AccessDeniedException.denyExecuteFunction;
import static io.trino.spi.security.AccessDeniedException.denyGrantRoles;
import static io.trino.spi.security.AccessDeniedException.denyGrantTablePrivilege;
import static io.trino.spi.security.AccessDeniedException.denyInsertTable;
import static io.trino.spi.security.AccessDeniedException.denyRefreshMaterializedView;
import static io.trino.spi.security.AccessDeniedException.denyRenameColumn;
import static io.trino.spi.security.AccessDeniedException.denyRenameMaterializedView;
import static io.trino.spi.security.AccessDeniedException.denyRenameTable;
import static io.trino.spi.security.AccessDeniedException.denyRenameView;
import static io.trino.spi.security.AccessDeniedException.denyRevokeRoles;
import static io.trino.spi.security.AccessDeniedException.denyRevokeTablePrivilege;
import static io.trino.spi.security.AccessDeniedException.denySelectColumns;
import static io.trino.spi.security.AccessDeniedException.denySetMaterializedViewProperties;
import static io.trino.spi.security.AccessDeniedException.denySetTableAuthorization;
import static io.trino.spi.security.AccessDeniedException.denySetTableProperties;
import static io.trino.spi.security.AccessDeniedException.denySetViewAuthorization;
import static io.trino.spi.security.AccessDeniedException.denyShowColumns;
import static io.trino.spi.security.AccessDeniedException.denyShowCreateTable;
import static io.trino.spi.security.AccessDeniedException.denyShowSchemas;
import static io.trino.spi.security.AccessDeniedException.denyTruncateTable;
import static io.trino.spi.security.AccessDeniedException.denyUpdateTableColumns;
import static io.trino.spi.security.AccessDeniedException.denyWriteSystemInformationAccess;
import static java.lang.String.format;

public class ForepaasAccessControl
        implements SystemAccessControl
{
    public static final String NAME = "forepaas-access-control";
    private static final ForepaasAccessControl INSTANCE = new ForepaasAccessControl();
    private static final File CONFIG_FILE = new File("etc/access-control.properties");
    private static final String URL_PROPERTY = "access-control.url";
    private static final Logger log = Logger.get(ForepaasAccessControl.class);
    private String opaServerUrl;

    public static class Factory
            implements SystemAccessControlFactory
    {
        @Override
        public String getName()
        {
            return NAME;
        }

        @Override
        public SystemAccessControl create(Map<String, String> config)
        {
            return INSTANCE;
        }
    }

    @Override
    public void checkCanSetUser(Optional<Principal> principal, String userName)
    {
    }

    @Override
    public void checkCanExecuteQuery(SystemSecurityContext context)
    {
    }

    @Override
    public void checkCanViewQueryOwnedBy(SystemSecurityContext context, Identity queryOwner)
    {
    }

    @Override
    public void checkCanKillQueryOwnedBy(SystemSecurityContext context, Identity queryOwner)
    {
    }

    @Override
    public void checkCanReadSystemInformation(SystemSecurityContext context)
    {
    }

    @Override
    public void checkCanWriteSystemInformation(SystemSecurityContext context)
    {
        denyWriteSystemInformationAccess();
    }

    @Override
    public void checkCanSetSystemSessionProperty(SystemSecurityContext context, String propertyName)
    {
    }

    @Override
    public void checkCanAccessCatalog(SystemSecurityContext context, String catalogName)
    {
        if (!checkCatalogByUserPrefix(context.getIdentity(), catalogName)) {
            denyCatalogAccess(catalogName);
        }
    }

    @Override
    public void checkCanCreateCatalog(SystemSecurityContext context, String catalogName)
    {
        if (!checkCatalogByUserPrefix(context.getIdentity(), catalogName)) {
            denyCreateCatalog(catalogName);
        }
    }

    @Override
    public void checkCanDropCatalog(SystemSecurityContext context, String catalogName)
    {
        if (!checkCatalogByUserPrefix(context.getIdentity(), catalogName)) {
            denyDropCatalog(catalogName);
        }
    }

    @Override
    public Set<String> filterCatalogs(SystemSecurityContext context, Set<String> catalogs)
    {
        ImmutableSet.Builder<String> filteredCatalogs = ImmutableSet.builder();
        for (String catalog : catalogs) {
//            import static io.trino.plugin.base.security.CatalogAccessControlRule.AccessMode.NONE;
//            if (canAccessCatalog(context.getIdentity(), catalog, NONE)) {
            if (checkCatalogByUserPrefix(context.getIdentity(), catalog)) {
                filteredCatalogs.add(catalog);
            }
        }
        return filteredCatalogs.build();
    }

    public Boolean checkCatalogByUserPrefix(Identity identity, String catalogName)
    {
//        Format: userId = dataplantId_userId , catalogName = db_dataplantId_catalogName
        String user = identity.getUser();
//        If user is admin, return true, if not, check if user is in the same dataplantId
        if ("admin".equals(user)) {
            return true;
        }
//        Avoid the case catalogName is not in the format of db_dataplantId_catalogName like catalog1
//        Avoid user is not in the format of dataplantId_userId like user1
        if (!catalogName.contains("_") || !user.contains("_")) {
            return false;
        }
        return catalogName.split("_")[1].equals(user.split("_")[0]);
    }

    public String getDataplantIdByIdentity(Identity identity)
    {
        String user = identity.getUser();
        if ("admin".equals(user)) {
            return "admin";
        }
        if (!user.contains("_")) {
            return user;
        }
        return user.split("_")[0];
    }

    @Override
    public void checkCanCreateSchema(SystemSecurityContext context, CatalogSchemaName schema, Map<String, Object> properties)
    {
    }

    @Override
    public void checkCanDropSchema(SystemSecurityContext context, CatalogSchemaName schema)
    {
    }

    @Override
    public void checkCanRenameSchema(SystemSecurityContext context, CatalogSchemaName schema, String newSchemaName)
    {
    }

    @Override
    public void checkCanSetSchemaAuthorization(SystemSecurityContext context, CatalogSchemaName schema, TrinoPrincipal principal)
    {
    }

    @Override
    public void checkCanShowSchemas(SystemSecurityContext context, String catalogName)
    {
        if (!canAccessCatalog(context.getIdentity(), catalogName, READ_ONLY)) {
            denyShowSchemas();
        }
    }

    @Override
    public Set<String> filterSchemas(SystemSecurityContext context, String catalogName, Set<String> schemaNames)
    {
        return schemaNames;
    }

    @Override
    public void checkCanShowCreateSchema(SystemSecurityContext context, CatalogSchemaName schemaName)
    {
    }

    @Override
    public void checkCanShowCreateTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denyShowCreateTable(table.toString());
        }
    }

    @Override
    public void checkCanCreateTable(SystemSecurityContext context, CatalogSchemaTableName table, Map<String, Object> properties)
    {
        // check if user will be an owner of the table after creation
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denyCreateTable(table.toString());
        }
    }

    public void checkCanDropTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denyDropTable(table.toString());
        }
    }

    @Override
    public void checkCanRenameTable(SystemSecurityContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable)
    {
        // check if user is an owner current table and will be an owner of the renamed table
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP) || !canAccessTable(context.getIdentity(), newTable, OWNERSHIP)) {
            denyRenameTable(table.toString(), newTable.toString());
        }
    }

    @Override
    public void checkCanSetTableProperties(SystemSecurityContext context, CatalogSchemaTableName table, Map<String, Optional<Object>> properties)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denySetTableProperties(table.toString());
        }
    }

    @Override
    public void checkCanSetTableComment(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denyCommentTable(table.toString());
        }
    }

    @Override
    public void checkCanSetViewComment(SystemSecurityContext context, CatalogSchemaTableName view)
    {
        if (!canAccessTable(context.getIdentity(), view, OWNERSHIP)) {
            denyCommentView(view.toString());
        }
    }

    @Override
    public void checkCanSetColumnComment(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denyCommentColumn(table.toString());
        }
    }

    @Override
    public void checkCanShowTables(SystemSecurityContext context, CatalogSchemaName schema)
    {
    }

    @Override
    public Set<SchemaTableName> filterTables(SystemSecurityContext context, String catalogName, Set<SchemaTableName> tableNames)
    {
        return tableNames;
    }

    @Override
    public void checkCanShowColumns(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!canAccessTable(context.getIdentity(), table, SELECT)) {
            denyShowColumns(table.toString());
        }
    }

    @Override
    public Set<String> filterColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns)
    {
        return columns;
    }

    @Override
    public void checkCanAddColumn(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denyAddColumn(table.toString());
        }
    }

    @Override
    public void checkCanAlterColumn(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denyAlterColumn(table.toString());
        }
    }

    @Override
    public void checkCanDropColumn(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denyDropColumn(table.toString());
        }
    }

    @Override
    public void checkCanSetTableAuthorization(SystemSecurityContext context, CatalogSchemaTableName table, TrinoPrincipal principal)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denySetTableAuthorization(table.toString(), principal);
        }
    }

    @Override
    public void checkCanRenameColumn(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denyRenameColumn(table.toString());
        }
    }

    @Override
    public void checkCanSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns)
    {
        if (!canAccessTable(context.getIdentity(), table, SELECT)) {
            denySelectColumns(table.toString(), columns);
        }
    }

    @Override
    public void checkCanInsertIntoTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!canAccessTable(context.getIdentity(), table, INSERT)) {
            denyInsertTable(table.toString());
        }
    }

    @Override
    public void checkCanDeleteFromTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!canAccessTable(context.getIdentity(), table, DELETE)) {
            denyDeleteTable(table.toString());
        }
    }

    @Override
    public void checkCanTruncateTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!canAccessTable(context.getIdentity(), table, DELETE)) {
            denyTruncateTable(table.toString());
        }
    }

    @Override
    public void checkCanUpdateTableColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> updatedColumnNames)
    {
        if (!canAccessTable(context.getIdentity(), table, UPDATE)) {
            denyUpdateTableColumns(table.toString(), updatedColumnNames);
        }
    }

    @Override
    public void checkCanCreateView(SystemSecurityContext context, CatalogSchemaTableName view)
    {
        // check if user will be an owner of the view after creation
        if (!canAccessTable(context.getIdentity(), view, OWNERSHIP)) {
            denyCreateView(view.toString());
        }
    }

    @Override
    public void checkCanRenameView(SystemSecurityContext context, CatalogSchemaTableName view, CatalogSchemaTableName newView)
    {
        // check if user owns the existing view, and if they will be an owner of the view after the rename
        if (!canAccessTable(context.getIdentity(), view, OWNERSHIP) || !canAccessTable(context.getIdentity(), newView, OWNERSHIP)) {
            denyRenameView(view.toString(), newView.toString());
        }
    }

    @Override
    public void checkCanSetViewAuthorization(SystemSecurityContext context, CatalogSchemaTableName view, TrinoPrincipal principal)
    {
        if (!canAccessTable(context.getIdentity(), view, OWNERSHIP)) {
            denySetViewAuthorization(view.toString(), principal);
        }
    }

    @Override
    public void checkCanDropView(SystemSecurityContext context, CatalogSchemaTableName view)
    {
        if (!canAccessTable(context.getIdentity(), view, OWNERSHIP)) {
            denyDropView(view.toString());
        }
    }

    @Override
    public void checkCanCreateViewWithSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denyCreateViewWithSelect(table.toString(), context.getIdentity());
        }
    }

    @Override
    public void checkCanCreateMaterializedView(SystemSecurityContext context, CatalogSchemaTableName materializedView, Map<String, Object> properties)
    {
        // check if user will be an owner of the view after creation
        if (!canAccessTable(context.getIdentity(), materializedView, OWNERSHIP)) {
            denyCreateMaterializedView(materializedView.toString());
        }
    }

    @Override
    public void checkCanRefreshMaterializedView(SystemSecurityContext context, CatalogSchemaTableName materializedView)
    {
        if (!canAccessTable(context.getIdentity(), materializedView, UPDATE)) {
            denyRefreshMaterializedView(materializedView.toString());
        }
    }

    @Override
    public void checkCanSetMaterializedViewProperties(SystemSecurityContext context, CatalogSchemaTableName materializedView, Map<String, Optional<Object>> properties)
    {
        if (!canAccessTable(context.getIdentity(), materializedView, OWNERSHIP)) {
            denySetMaterializedViewProperties(materializedView.toString());
        }
    }

    @Override
    public void checkCanDropMaterializedView(SystemSecurityContext context, CatalogSchemaTableName materializedView)
    {
        if (!canAccessTable(context.getIdentity(), materializedView, OWNERSHIP)) {
            denyDropMaterializedView(materializedView.toString());
        }
    }

    @Override
    public void checkCanRenameMaterializedView(SystemSecurityContext context, CatalogSchemaTableName view, CatalogSchemaTableName newView)
    {
        // check if user owns the existing materialized view, and if they will be an owner of the materialized view after the rename
        if (!canAccessTable(context.getIdentity(), view, OWNERSHIP) || !canAccessTable(context.getIdentity(), newView, OWNERSHIP)) {
            denyRenameMaterializedView(view.toString(), newView.toString());
        }
    }

    @Override
    public void checkCanGrantExecuteFunctionPrivilege(SystemSecurityContext context, String functionName, TrinoPrincipal grantee, boolean grantOption)
    {
    }

    @Override
    public void checkCanGrantExecuteFunctionPrivilege(SystemSecurityContext context, FunctionKind functionKind, CatalogSchemaRoutineName functionName, TrinoPrincipal grantee, boolean grantOption)
    {
    }

    @Override
    public void checkCanSetCatalogSessionProperty(SystemSecurityContext context, String catalogName, String propertyName)
    {
    }

    @Override
    public void checkCanGrantSchemaPrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaName schema, TrinoPrincipal grantee, boolean grantOption)
    {
    }

    @Override
    public void checkCanDenySchemaPrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaName schema, TrinoPrincipal grantee)
    {
    }

    @Override
    public void checkCanRevokeSchemaPrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaName schema, TrinoPrincipal revokee, boolean grantOption)
    {
    }

    @Override
    public void checkCanGrantTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal grantee, boolean grantOption)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denyGrantTablePrivilege(privilege.name(), table.toString());
        }
    }

    @Override
    public void checkCanDenyTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal grantee)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denyDenyTablePrivilege(privilege.name(), table.toString());
        }
    }

    @Override
    public void checkCanRevokeTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal revokee, boolean grantOption)
    {
        if (!canAccessTable(context.getIdentity(), table, OWNERSHIP)) {
            denyRevokeTablePrivilege(privilege.name(), table.toString());
        }
    }

    @Override
    public void checkCanShowRoles(SystemSecurityContext context)
    {
        // allow, no roles are supported so show will always be empty
    }

    @Override
    public void checkCanCreateRole(SystemSecurityContext context, String role, Optional<TrinoPrincipal> grantor)
    {
        denyCreateRole(role);
    }

    @Override
    public void checkCanDropRole(SystemSecurityContext context, String role)
    {
        denyDropRole(role);
    }

    @Override
    public void checkCanGrantRoles(SystemSecurityContext context, Set<String> roles, Set<TrinoPrincipal> grantees, boolean adminOption, Optional<TrinoPrincipal> grantor)
    {
        denyGrantRoles(roles, grantees);
    }

    @Override
    public void checkCanRevokeRoles(SystemSecurityContext context, Set<String> roles, Set<TrinoPrincipal> grantees, boolean adminOption, Optional<TrinoPrincipal> grantor)
    {
        denyRevokeRoles(roles, grantees);
    }

    @Override
    public void checkCanShowRoleAuthorizationDescriptors(SystemSecurityContext context)
    {
        // allow, no roles are supported so show will always be empty
    }

    @Override
    public void checkCanShowCurrentRoles(SystemSecurityContext context)
    {
        // allow, no roles are supported so show will always be empty
    }

    @Override
    public void checkCanShowRoleGrants(SystemSecurityContext context)
    {
        // allow, no roles are supported so show will always be empty
    }

    @Override
    public void checkCanExecuteProcedure(SystemSecurityContext systemSecurityContext, CatalogSchemaRoutineName procedure)
    {
    }

    @Override
    public void checkCanExecuteFunction(SystemSecurityContext systemSecurityContext, String functionName)
    {
        denyExecuteFunction(functionName);
    }

    @Override
    public void checkCanExecuteFunction(SystemSecurityContext systemSecurityContext, FunctionKind functionKind, CatalogSchemaRoutineName functionName)
    {
        denyExecuteFunction(functionName.toString());
    }

    @Override
    public void checkCanExecuteTableProcedure(SystemSecurityContext systemSecurityContext, CatalogSchemaTableName table, String procedure)
    {
    }

    @Override
    public List<ViewExpression> getRowFilters(SystemSecurityContext context, CatalogSchemaTableName tableName)
    {
        return ImmutableList.of();
    }

    @Override
    public Optional<ViewExpression> getColumnMask(SystemSecurityContext context, CatalogSchemaTableName tableName, String columnName, Type type)
    {
        return Optional.empty();
    }

    private boolean canAccessCatalog(Identity identity, String catalogName, CatalogAccessControlRule.AccessMode accessMode)
    {
        Map<String, Object> body = new HashMap<>();
        body.put("Service", "adac");
        body.put("Resource", "dataset");
        body.put("Action", accessMode);
        body.put("Id", catalogName);
        body.put("Name", catalogName);
        body.put("Path", catalogName);
        body.put("Timestamp", System.currentTimeMillis());
        body.put("Sub", identity.getUser());
        body.put("DataplantId", getDataplantIdByIdentity(identity));
        body.put("Attributes", "{}");
        body.put("WithConditions", true);
        return isOpaAllowed(body);
    }

    private boolean canAccessTable(Identity identity, CatalogSchemaTableName table, TableAccessControlRule.TablePrivilege requiredPrivilege)
    {
        CatalogAccessControlRule.AccessMode requiredCatalogAccess = requiredPrivilege == SELECT || requiredPrivilege == GRANT_SELECT ? READ_ONLY : ALL;
        Map<String, Object> body = new HashMap<>();
        body.put("Service", "adac");
        body.put("Resource", "table");
        body.put("Action", requiredCatalogAccess);
        body.put("Id", format("%s.%s.%s", table.getCatalogName(), table.getSchemaTableName().getSchemaName(), table.getSchemaTableName().getTableName()));
        body.put("Name", table.getSchemaTableName().getTableName());
        body.put("Path", format("%s.%s", table.getCatalogName(), table.getSchemaTableName().getSchemaName()));
        body.put("Timestamp", System.currentTimeMillis());
        body.put("Sub", identity.getUser());
        body.put("DataplantId", getDataplantIdByIdentity(identity));
        body.put("Attributes", "{}");
        body.put("WithConditions", true);
        return isOpaAllowed(body);
    }

////        TODO: Can pass this check
//    private boolean canAccessQuery(Identity identity, QueryAccessRule.AccessMode accessMode)
//    {
//        Map<String, Object> body = Map.of(
//                "type", "QueryAccess",
//                "user", identity.getUser(),
//                "catalog", identity.getEnabledRoles(),
//                "schema", identity.getGroups(),
//                "access_mode", accessMode);
//        return isOpaAllowed(body);
//    }

////        TODO: Can pass this check
//    private boolean canSystemInformation(Identity identity, SystemInformationRule.AccessMode requiredAccess)
//    {
//        Map<String, Object> body = Map.of(
//                "type", "SystemInformation",
//                "user", identity.getUser(),
//                "access_mode", requiredAccess);
//        return isOpaAllowed(body);
//    }

////        TODO: Can pass this check
//    private boolean canSystemProperty(Identity identity, String propertyName)
//    {
//        Map<String, Object> body = Map.of(
//                "service", "adac",
//                "resource", "system",
//                "action", "read",
//                "id", "??",
//                "path", "",
//                "timestamp", "",
//                "name", propertyName,
//                "user", identity.getUser(),
//                "catalog", identity.getEnabledRoles(),
//                "schema", identity.getGroups());
//        return isOpaAllowed(body);
//    }

    private boolean isOpaAllowed(Map<String, Object> input)
    {
        try {
            // Get url from access-control.properties
            if (isNullOrEmpty(this.opaServerUrl)) {
                this.opaServerUrl = getUrlFromProperties();
            }

            URL url = new URL(this.opaServerUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);
            // Prepare input for OPA server
            Map<String, Object> body = new HashMap<>();
            body.put("query", "allow = data.iam.allow");
            body.put("input", input);
            String jsonInput = new ObjectMapper().writeValueAsString(body);
            try (OutputStream os = connection.getOutputStream()) {
                byte[] inputBytes = jsonInput.getBytes(StandardCharsets.UTF_8);
                os.write(inputBytes, 0, inputBytes.length);
            }

            // Send POST request to OPA server and parse response to get the access decision
            int responseCode = connection.getResponseCode();
            log.info("ForepaasAccessControl.isOpaAllowed: responseCode" + responseCode);
            if (responseCode == HttpURLConnection.HTTP_OK) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                    String responseJson = reader.readLine();
                    Map<String, Object> response = new ObjectMapper().readValue(responseJson, Map.class);
                    Object result = response.get("result");
                    if (result instanceof List) {
                        List<Map<String, Object>> resultList = (List<Map<String, Object>>) result;
                        if (!resultList.isEmpty()) {
                            Map<String, Object> resultEntry = resultList.get(0);
                            Object allowValue = resultEntry.get("allow");
                            if (allowValue instanceof Boolean) {
                                return (Boolean) allowValue;
                            }
                        }
                    }
                }
                return false; // Default case: OPA response does not match expected format
            }
            else {
                throw new RuntimeException("Failed to communicate with OPA server, HTTP error code: " + responseCode);
            }
        }
        catch (IOException e) {
            throw new RuntimeException("Failed to communicate with OPA server", e);
        }
    }

    private String getUrlFromProperties()
    {
        Map<String, String> properties;
        try {
            properties = new HashMap<>(loadPropertiesFrom(CONFIG_FILE.getPath()));
        }
        catch (IOException e) {
            throw new UncheckedIOException("Failed to read configuration file: " + CONFIG_FILE, e);
        }
        String url = properties.remove(URL_PROPERTY);
        checkState(!isNullOrEmpty(url), "Access control configuration does not contain '%s' property: %s", URL_PROPERTY, CONFIG_FILE);
        return url;
    }
}
