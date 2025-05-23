# User Guides

## Table of Contents

1. [Getting Started](#getting-started)
2. [Creating Your First Semantic Model](#creating-your-first-semantic-model)
3. [Building Business Models](#building-business-models)
4. [Creating Presentation Layers](#creating-presentation-layers)
5. [Querying Data](#querying-data)
6. [User Management](#user-management)
7. [Security and Permissions](#security-and-permissions)
8. [BI Tool Integration](#bi-tool-integration)
9. [Best Practices](#best-practices)
10. [Troubleshooting](#troubleshooting)

---

## Getting Started

### What is the Universal Semantic Layer?

The Universal Semantic Layer Application provides a business-friendly abstraction over your organization's data sources. It transforms technical database schemas into intuitive business models that anyone can understand and query, regardless of their technical expertise.

### Key Concepts

- **Physical Layer**: The actual database tables and columns in your data sources
- **Business Layer**: Business-friendly names, calculations, and relationships
- **Presentation Layer**: Customized views for different user groups and use cases
- **Semantic Model**: The complete three-layer structure that defines how data is accessed

### Logging In

1. Navigate to the application URL provided by your administrator
2. Enter your username and password
3. If MFA is enabled, enter your authentication code
4. Click "Sign In"

### Dashboard Overview

After logging in, you'll see the main dashboard with:

- **Recent Models**: Models you've recently worked with
- **Saved Queries**: Your saved and shared queries
- **Data Sources**: Available data connections
- **Quick Actions**: Common tasks like creating models or running queries

---

## Creating Your First Semantic Model

### Step 1: Connect to a Data Source

1. Navigate to **Data Sources** → **Add New**
2. Select your database type (PostgreSQL, MySQL, SQL Server, etc.)
3. Enter connection details:
   - **Name**: A descriptive name for your data source
   - **Host**: Database server address
   - **Port**: Database port (usually default)
   - **Database**: Database name
   - **Username/Password**: Database credentials
4. Click **Test Connection** to verify
5. Save the data source

### Step 2: Create a Physical Model

1. Go to **Models** → **Create New** → **Physical Model**
2. Select your data source
3. Choose import method:
   - **Import All Tables**: Import entire schema
   - **Select Tables**: Choose specific tables
   - **Manual Definition**: Define tables manually

4. Review imported tables and columns
5. Define relationships between tables:
   - Primary keys are auto-detected
   - Foreign key relationships can be auto-discovered or manually defined
6. Save your physical model

### Step 3: Build a Business Model

1. Click **Create Business Model** from your physical model
2. Define business entities:
   - Map physical tables to business entities
   - Give business-friendly names (e.g., "customers" → "Customer")
   - Add descriptions for clarity

3. Configure attributes:
   - Map physical columns to business attributes
   - Use descriptive names (e.g., "cust_id" → "Customer ID")
   - Set data types and formatting

4. Create calculated metrics:
   - Define business calculations (e.g., "Total Revenue", "Average Order Value")
   - Use formulas like `SUM(order_amount)` or `COUNT(DISTINCT customer_id)`

5. Set up hierarchies:
   - Create drill-down paths (e.g., Year → Quarter → Month)
   - Define geographic hierarchies (Country → State → City)

### Step 4: Create a Presentation Model

1. Select **Create Presentation Model** from your business model
2. Define subject areas:
   - Group related entities and metrics
   - Create focused views for different user types

3. Configure perspectives:
   - Set default dimensions and metrics
   - Apply security filters
   - Customize for different roles

4. Publish your model for end users

---

## Building Business Models

### Entities

Entities represent business concepts like Customer, Product, or Order.

#### Creating an Entity
1. In your business model, click **Add Entity**
2. Select the physical table to map
3. Configure entity properties:
   - **Name**: Business-friendly name
   - **Display Name**: Name shown to users
   - **Description**: What this entity represents
   - **Icon**: Visual representation (optional)

#### Entity Relationships
Define how entities relate to each other:
- **One-to-Many**: One customer has many orders
- **Many-to-One**: Many orders belong to one customer
- **Many-to-Many**: Products can be in many categories, categories have many products

### Attributes

Attributes are the individual data points within entities.

#### Creating Attributes
1. Select an entity and click **Add Attribute**
2. Map to a physical column
3. Configure properties:
   - **Name**: Technical name (camelCase)
   - **Display Name**: User-friendly name
   - **Data Type**: String, Number, Date, Boolean
   - **Format**: Display formatting rules
   - **Nullable**: Whether empty values are allowed

#### Attribute Types
- **Key Attributes**: Unique identifiers
- **Descriptive Attributes**: Text descriptions
- **Categorical Attributes**: Categories or types
- **Numerical Attributes**: Quantities or measures

### Metrics

Metrics are calculated values that provide business insights.

#### Creating Metrics
1. Click **Add Metric** in your business model
2. Configure the metric:
   - **Name**: Technical identifier
   - **Display Name**: User-friendly name
   - **Formula**: Calculation logic
   - **Aggregation**: How to combine values (SUM, AVG, COUNT, etc.)
   - **Format**: Number formatting (currency, percentage, etc.)

#### Common Metric Patterns
```sql
-- Revenue Metrics
Total Revenue: SUM(order_amount)
Average Order Value: AVG(order_amount)
Monthly Recurring Revenue: SUM(subscription_amount)

-- Count Metrics  
Customer Count: COUNT(DISTINCT customer_id)
Order Count: COUNT(order_id)
New Customers: COUNT(DISTINCT CASE WHEN first_order_date = order_date THEN customer_id END)

-- Ratio Metrics
Conversion Rate: COUNT(DISTINCT order_customer_id) / COUNT(DISTINCT website_visitor_id)
Profit Margin: (SUM(revenue) - SUM(cost)) / SUM(revenue)
```

### Hierarchies

Hierarchies enable drill-down analysis.

#### Date Hierarchy Example
1. Create hierarchy named "Date Hierarchy"
2. Add levels:
   - **Year**: Extract year from date field
   - **Quarter**: Extract quarter from date field  
   - **Month**: Extract month from date field
   - **Day**: The date field itself

#### Geographic Hierarchy Example
1. Create hierarchy named "Geographic Hierarchy"
2. Add levels:
   - **Country**: Country field
   - **State/Province**: State field
   - **City**: City field
   - **Postal Code**: Postal code field

---

## Creating Presentation Layers

### Subject Areas

Subject areas group related entities and metrics for specific business domains.

#### Sales Subject Area Example
- **Entities**: Customer, Order, Product
- **Key Metrics**: Total Revenue, Order Count, Average Order Value
- **Common Dimensions**: Customer Segment, Product Category, Order Date
- **Target Users**: Sales team, executives

#### Marketing Subject Area Example  
- **Entities**: Campaign, Lead, Customer
- **Key Metrics**: Cost per Lead, Conversion Rate, Return on Ad Spend
- **Common Dimensions**: Campaign Type, Channel, Date
- **Target Users**: Marketing team, digital marketers

### Perspectives

Perspectives provide customized views of subject areas for different user roles.

#### Executive Perspective
- **Focus**: High-level KPIs and trends
- **Default View**: Revenue, customer count, growth rates by quarter
- **Access**: All data, no filters
- **Visualizations**: Charts and dashboards

#### Regional Manager Perspective
- **Focus**: Regional performance
- **Default View**: Regional metrics and comparisons
- **Access**: Filtered to user's region only
- **Security Rule**: `Customer.region = @user.region`

#### Analyst Perspective
- **Focus**: Detailed analysis capabilities
- **Default View**: Flexible querying interface
- **Access**: Full analytical capabilities
- **Tools**: Query builder, advanced filters

---

## Querying Data

### Visual Query Builder

The visual query builder allows you to create queries without writing SQL.

#### Building a Query
1. Select **New Query** from the dashboard
2. Choose your presentation model
3. Add dimensions (attributes to group by):
   - Drag attributes from the entity tree
   - Or click the + button next to attributes
4. Add metrics (values to calculate):
   - Select from available metrics
   - Configure aggregation if needed
5. Apply filters:
   - Click **Add Filter**
   - Choose attribute, operator, and value
   - Combine filters with AND/OR logic
6. Configure sorting and limits
7. Run the query

#### Query Example: Top Customers by Revenue
```
Dimensions: Customer Name, Customer Segment
Metrics: Total Revenue, Order Count  
Filters: Order Date >= 2024-01-01
Sort: Total Revenue (Descending)
Limit: 10
```

### Advanced Filtering

#### Filter Operators
- **Equals**: Exact match
- **Not Equals**: Exclude exact matches
- **Contains**: Text contains substring
- **In**: Value is in a list
- **Between**: Value is within a range
- **Greater Than/Less Than**: Numerical comparisons
- **Is Null/Is Not Null**: Missing data checks

#### Date Filters
- **Relative Dates**: Last 30 days, This quarter, Previous year
- **Date Ranges**: Specific start and end dates
- **Date Parts**: Specific months, days of week, etc.

#### Parameter Queries
Create reusable queries with parameters:
1. Add parameter: `@start_date`, `@customer_segment`
2. Use in filters: `Order Date >= @start_date`
3. Users enter values when running the query

### Saving and Sharing Queries

#### Saving Queries
1. After building your query, click **Save**
2. Provide a name and description
3. Choose visibility:
   - **Private**: Only you can see it
   - **Shared**: Others with access can use it
   - **Public**: Everyone in organization can see it

#### Query Collections
Organize related queries into collections:
- **Sales Dashboard Queries**: Revenue, customer, and product queries
- **Marketing Analysis**: Campaign and lead generation queries
- **Executive Reports**: High-level KPI queries

---

## User Management

### Managing Your Profile

#### Updating Personal Information
1. Click your profile picture → **Profile Settings**
2. Update personal details:
   - Name and contact information
   - Profile picture
   - Notification preferences
   - Default time zone

#### Changing Password
1. Go to **Profile Settings** → **Security**
2. Click **Change Password**
3. Enter current password and new password
4. Confirm the change

#### Setting Up MFA
1. Navigate to **Profile Settings** → **Security**
2. Click **Enable Multi-Factor Authentication**
3. Scan QR code with authenticator app
4. Enter verification code
5. Save backup codes in a secure location

### Team Collaboration

#### Sharing Models
- **View Access**: Users can see and query the model
- **Edit Access**: Users can modify the model
- **Admin Access**: Users can manage permissions

#### Commenting and Annotations
- Add comments to models, entities, and attributes
- Use `@username` to notify team members
- Track change history and discussions

#### Workspace Organization
- Create workspaces for different teams or projects
- Organize models by business domain
- Set workspace-level permissions

---

## Security and Permissions

### Understanding Roles

#### Built-in Roles
- **Viewer**: Can view and query existing models
- **Analyst**: Can create queries and personal models
- **Modeler**: Can create and modify shared models
- **Admin**: Full system administration access

#### Custom Roles
Create roles tailored to your organization:
1. Go to **Administration** → **Roles**
2. Click **Create Role**
3. Define permissions:
   - Model access (read, write, admin)
   - Query capabilities
   - User management
   - System administration
4. Assign data access rules

### Data Security

#### Row-Level Security
Restrict data access based on user attributes:
```
Rule: Customer.region = @user.region
Effect: Users only see customers in their assigned region

Rule: Order.sales_rep = @user.employee_id  
Effect: Sales reps only see their own customers' orders
```

#### Column-Level Security
Hide sensitive columns from certain users:
- **Credit Card Numbers**: Hidden from most users
- **Social Security Numbers**: Restricted to HR only
- **Salary Information**: Visible to managers only

#### Data Masking
Partially hide sensitive data:
- **Email**: Show first 3 characters + ***@domain.com
- **Phone**: Show area code + ***-****
- **Names**: Show first name + last initial

### Audit and Compliance

#### Activity Monitoring
Track user activities:
- Model access and modifications
- Query execution and results
- Data exports and downloads
- Login/logout events

#### Compliance Reports
Generate reports for:
- **GDPR**: Data access and processing logs
- **SOX**: Data access controls and changes
- **HIPAA**: Healthcare data access tracking
- **Custom**: Organization-specific requirements

---

## BI Tool Integration

### Tableau Integration

#### Connecting Tableau to Semantic Layer
1. Install the Semantic Layer connector for Tableau
2. In Tableau, select **More...** → **Semantic Layer** connector
3. Enter connection details:
   - Server URL
   - Username and password
   - Or API key authentication
4. Select your presentation model
5. Start building visualizations

#### Best Practices for Tableau
- Use semantic layer metrics instead of creating calculated fields
- Leverage pre-built hierarchies for drill-down
- Apply semantic layer security rather than Tableau filters
- Create extract schedules to refresh semantic layer data

### Power BI Integration

#### Connecting Power BI
1. In Power BI Desktop, click **Get Data**
2. Search for "Semantic Layer" connector
3. Authenticate and select data model
4. Import entities and metrics as tables
5. Create relationships in Power BI model

#### Power BI Optimization
- Use DirectQuery for real-time data
- Import mode for better performance with smaller datasets
- Leverage semantic layer caching for faster queries

### Looker Integration

#### Native LookML Generation
1. Export LookML from your semantic model
2. Import generated files into Looker project
3. Customize visualizations and dashboards
4. Maintain sync with semantic layer changes

### Custom Integrations

#### JDBC/ODBC Connection
Most BI tools can connect via standard database drivers:
```
Connection String: 
jdbc:semantic://your-server:port/model_id

Driver Class: 
com.semanticlayer.jdbc.Driver
```

#### REST API Integration
For custom applications:
```javascript
// Execute query via API
const response = await fetch('/api/v1/queries/execute', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + token,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(queryDefinition)
});
```

---

## Best Practices

### Model Design

#### Physical Layer Best Practices
- **Import Complete Schemas**: Include all tables and relationships
- **Document Everything**: Add descriptions to tables and columns
- **Maintain Relationships**: Ensure foreign keys are properly defined
- **Regular Sync**: Keep physical models in sync with source systems

#### Business Layer Best Practices
- **Use Clear Names**: Choose intuitive, business-friendly names
- **Consistent Naming**: Follow naming conventions (e.g., PascalCase for entities)
- **Meaningful Descriptions**: Explain what each entity and attribute represents
- **Logical Grouping**: Organize related entities together
- **Validate Metrics**: Test calculations against known results
- **Version Control**: Track changes and maintain model history

#### Presentation Layer Best Practices
- **User-Centric Design**: Design perspectives for specific user needs
- **Security by Default**: Apply appropriate access controls
- **Performance Optimization**: Limit default result sets
- **Documentation**: Provide clear guidance for each perspective
- **Regular Review**: Update perspectives based on user feedback

### Performance Optimization

#### Query Performance
- **Use Filters**: Always apply appropriate filters to limit data
- **Limit Result Sets**: Use pagination for large queries
- **Leverage Indexes**: Ensure underlying tables are properly indexed
- **Cache Results**: Use semantic layer caching for repeated queries
- **Monitor Execution**: Track slow queries and optimize

#### Model Performance
- **Minimize Joins**: Reduce unnecessary table joins in physical model
- **Aggregate Tables**: Create summary tables for common metrics
- **Partition Large Tables**: Use partitioning for time-series data
- **Regular Maintenance**: Update statistics and optimize queries

### Security Best Practices

#### Access Control
- **Principle of Least Privilege**: Grant minimum necessary access
- **Regular Reviews**: Audit permissions quarterly
- **Role-Based Design**: Use roles instead of individual permissions
- **Separation of Duties**: Separate modeling and administrative roles

#### Data Protection
- **Encrypt Sensitive Data**: Use encryption for PII and confidential data
- **Audit Everything**: Log all data access and modifications
- **Secure Connections**: Use TLS for all communications
- **Regular Backups**: Maintain secure, tested backups

---

## Troubleshooting

### Common Issues

#### Connection Problems

**Issue**: Cannot connect to data source
**Solutions**:
1. Verify connection string and credentials
2. Check network connectivity and firewall rules
3. Ensure database server is running
4. Test with a database client tool first
5. Contact your database administrator

**Issue**: Connection timeout
**Solutions**:
1. Increase connection timeout settings
2. Check network latency
3. Verify database server performance
4. Consider connection pooling settings

#### Query Issues

**Issue**: Query returns no results
**Solutions**:
1. Check filter conditions - they may be too restrictive
2. Verify data exists in the underlying tables
3. Review join conditions in the physical model
4. Check security filters that might exclude data

**Issue**: Query runs slowly
**Solutions**:
1. Add appropriate filters to limit data scope
2. Check if underlying tables have proper indexes
3. Review query execution plan
4. Consider creating aggregated tables
5. Use caching for frequently-run queries

**Issue**: "Permission Denied" error
**Solutions**:
1. Verify user has access to the presentation model
2. Check role assignments
3. Review row-level security rules
4. Contact administrator for access

#### Model Issues

**Issue**: Physical model sync fails
**Solutions**:
1. Check data source connectivity
2. Verify database permissions for schema access
3. Review error logs for specific issues
4. Try importing specific tables instead of full schema

**Issue**: Business model validation errors
**Solutions**:
1. Check entity relationships are properly defined
2. Verify metric formulas use valid syntax
3. Ensure all referenced columns exist
4. Review attribute data type mappings

### Error Messages

#### Authentication Errors
- **"Invalid credentials"**: Check username and password
- **"Token expired"**: Log out and log back in
- **"MFA required"**: Enter your authentication code

#### Authorization Errors
- **"Access denied"**: Contact administrator for permissions
- **"Insufficient privileges"**: Request additional role assignments
- **"Resource not found"**: Verify the model or query exists

#### Validation Errors
- **"Invalid filter syntax"**: Check filter operators and values
- **"Unknown attribute"**: Verify attribute name spelling
- **"Circular reference"**: Review metric and hierarchy definitions

### Getting Help

#### Self-Service Resources
1. **Documentation**: Check this guide and API documentation
2. **Knowledge Base**: Search for known issues and solutions
3. **Community Forum**: Ask questions and share experiences
4. **Video Tutorials**: Watch step-by-step guidance

#### Contacting Support
1. **Help Desk**: Submit ticket through the application
2. **Email Support**: support@yourcompany.com
3. **Phone Support**: Available during business hours
4. **Emergency Escalation**: For critical production issues

#### Information to Include in Support Requests
- **User ID and Role**: Your username and assigned roles
- **Model Details**: Which model you're working with
- **Steps to Reproduce**: Exact steps that led to the issue
- **Error Messages**: Full text of any error messages
- **Screenshots**: Visual representation of the problem
- **Environment**: Production, staging, or development

### Maintenance and Updates

#### Regular Maintenance Tasks
- **Weekly**: Review slow queries and optimize
- **Monthly**: Update user access and roles
- **Quarterly**: Audit security settings and permissions
- **Annually**: Review and update data retention policies

#### Update Procedures
1. **Backup**: Always backup before major changes
2. **Test Environment**: Test changes in non-production first
3. **Staged Rollout**: Deploy to user groups gradually
4. **Monitor**: Watch for issues after deployment
5. **Rollback Plan**: Have a plan to revert if needed

#### Model Versioning
- **Version Tags**: Use semantic versioning (v1.0, v1.1, etc.)
- **Change Documentation**: Document what changed in each version
- **Backward Compatibility**: Maintain compatibility with existing queries
- **Deprecation Process**: Provide notice before removing features

---

## Appendix

### Keyboard Shortcuts

#### Query Builder
- `Ctrl+R` - Run query
- `Ctrl+S` - Save query
- `Ctrl+Z` - Undo last action
- `Ctrl+Y` - Redo last action
- `F5` - Refresh data preview

#### Model Designer
- `Ctrl+N` - Create new entity
- `Ctrl+D` - Duplicate selected item
- `Delete` - Remove selected item
- `F2` - Rename selected item
- `Ctrl+F` - Find/search in model

### Glossary

**Attribute**: A data field within an entity (e.g., Customer Name, Order Date)

**Business Layer**: The middle layer that provides business-friendly names and calculations

**Dimension**: An attribute used for grouping and filtering data

**Entity**: A business object or concept (e.g., Customer, Product, Order)

**Hierarchy**: A structured arrangement of dimensions for drill-down analysis

**Metric**: A calculated measure that provides business value (e.g., Total Revenue)

**Physical Layer**: The bottom layer representing actual database tables and columns

**Presentation Layer**: The top layer that provides customized views for end users

**Perspective**: A customized view of a subject area for specific user roles

**Semantic Model**: The complete three-layer structure that defines data access

**Subject Area**: A collection of related entities and metrics for a business domain

### Sample Data Models

#### E-commerce Model Structure
```
Entities:
- Customer (customer_id, name, email, segment, region)
- Product (product_id, name, category, price, cost)
- Order (order_id, customer_id, order_date, status)
- OrderItem (order_id, product_id, quantity, unit_price)

Key Metrics:
- Total Revenue: SUM(OrderItem.quantity * OrderItem.unit_price)
- Customer Count: COUNT(DISTINCT Customer.customer_id)
- Average Order Value: AVG(Order.total_amount)
- Profit Margin: (Revenue - Cost) / Revenue

Hierarchies:
- Date: Year → Quarter → Month → Day
- Product: Category → Subcategory → Product
- Geography: Country → State → City
```

#### SaaS Business Model Structure
```
Entities:
- Account (account_id, name, plan_type, created_date)
- User (user_id, account_id, email, role, last_login)
- Subscription (subscription_id, account_id, plan, start_date, end_date)
- Usage (usage_id, account_id, feature, usage_date, quantity)

Key Metrics:
- Monthly Recurring Revenue: SUM(Subscription.monthly_amount)
- Customer Acquisition Cost: Marketing_Spend / New_Customers
- Churn Rate: Cancelled_Subscriptions / Total_Subscriptions
- Lifetime Value: Average_Revenue_Per_Customer / Churn_Rate

Hierarchies:
- Time: Year → Quarter → Month
- Plan: Plan_Tier → Plan_Type → Individual_Plan
- Organization: Company → Department → User
```
