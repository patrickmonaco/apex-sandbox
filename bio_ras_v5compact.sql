-------------------------------------------------
SCRIPT pour RAS
Protection des données Bio Green
v0.5
12 dec 2019
-------------------------------------------------

grant  dba,xs_session_admin to rasadm identified by rasadm;
connect rasadm/rasadm

---------------------------------------------- Dec 2019
-- Tutorial
------------------------------------------------

https://docs.oracle.com/database/121/DBFSG/security_hr_demo_tutorial.htm#DBFSG813
-------------------------------------------------

create role db_bio;
grant select, insert, update, delete on DEMO.ADO_PLAN to db_bio; 
grant select on DEMO.COMMUNES to db_bio;

exec xs_principal.create_role(name => 'sr_role', enabled => true);
exec xs_principal.create_role(name => 'hq_role', enabled => true);
exec xs_principal.create_role(name => 'sa_role', enabled => true);

exec sys.xs_principal.create_role(name => 'sud_ventes', enabled => TRUE);
exec sys.xs_principal.create_role(name => 'nord_ventes', enabled => TRUE);
exec sys.xs_principal.create_role(name => 'est_ventes', enabled => TRUE);
exec sys.xs_principal.create_role(name => 'ouest_ventes', enabled => TRUE);
exec sys.xs_principal.create_role(name => 'centre_ventes', enabled => TRUE);

grant db_bio to sr_role;
grant db_bio to hq_role;
grant db_bio to sa_role;
grant db_bio to ouest_ventes;
grant db_bio to sud_ventes;
grant db_bio to nord_ventes;
grant db_bio to est_ventes;
grant db_bio to centre_ventes;


-- Directeur ventes
exec  xs_principal.create_user(name => 'alain', schema => 'DEMO');
exec  sys.xs_principal.set_password('alain', 'alain');
exec  xs_principal.grant_roles('alain', 'hq_role');

-- Responsable régional
exec  xs_principal.create_user(name => 'ygor', schema => 'DEMO');
exec  sys.xs_principal.set_password('ygor', 'ygor');
exec  xs_principal.grant_roles('ygor', 'ouest_ventes');

-- Commercial
exec  xs_principal.create_user(name => 'brice', schema => 'DEMO');
exec  sys.xs_principal.set_password('brice', 'brice');
exec  xs_principal.grant_roles('brice', 'sr_role');

-- Assistant commercial
exec  xs_principal.create_user(name => 'pierre', schema => 'DEMO');
exec  sys.xs_principal.set_password('pierre', 'pierre');
exec  xs_principal.grant_roles('pierre', 'sa_role');

------------------------------
Give create session privilege
------------------------------
BEGIN  
    SYS.XS_PRINCIPAL.GRANT_ROLES('ALAIN', 'XSCONNECT'); 
    SYS.XS_PRINCIPAL.GRANT_ROLES('YGOR', 'XSCONNECT'); 
    SYS.XS_PRINCIPAL.GRANT_ROLES('BRICE', 'XSCONNECT');
    SYS.XS_PRINCIPAL.GRANT_ROLES('PIERRE', 'XSCONNECT');
END;
/

---------------------------------------------
Create a security class bioprivs based on the predefined DML security class. 
bioprivs has a new privilege view_discount, which controls access to the DISCOUNT column.
----------------------------------------------

declare
begin
  xs_security_class.create_security_class(
    name        => 'bioprivs', 
    parent_list => xs$name_list('sys.dml'),
    priv_list   => xs$privilege_list(xs$privilege('view_discount')));
end;
/

-----------------------------------
Creating ACLs: EMP_ACL, IT_ACL, and HR_ACL
(Ace stands for Access Control Entry)
-----------------------------------

declare
      aces xs$ace_list := xs$ace_list();
    begin
      aces.extend(1);
    
-- SR_ACL: This ACL grants SR_ROLE the privileges to view a sales rep's
--          own record including DISCOUNT column.
   
   aces(1) := xs$ace_type(
            privilege_list => xs$name_list('select','view_discount'),
            principal_name => 'sr_role');
   
     sys.xs_acl.create_acl(
            name      => 'sr_acl',
            ace_list  => aces,
            sec_class => 'bioprivs');
   

-- HQ_ACL:  This ACL grants HQ_ROLE the privileges to view and update all
--          order records including DISCOUNT column.
  
  aces(1):= xs$ace_type(
         privilege_list => xs$name_list('all'),
         principal_name => 'hq_role');
   
    sys.xs_acl.create_acl(
        name      => 'hq_acl',
        ace_list  => aces,
        sec_class => 'bioprivs');
        
-- SA_ACL:  This ACL grants SA_ROLE the privileges to view and update all
--          order records excluding DISCOUNT column.
     aces(1):= xs$ace_type(
         privilege_list => xs$name_list('select'),
         principal_name => 'sa_role');
   
    sys.xs_acl.create_acl(
        name      => 'sa_acl',
        ace_list  => aces,
        sec_class => 'bioprivs');    
  end;
   /
  
  
-- eviter interpretation du & sous sqlplus 
set escape '#' 

-----------------------------------------------------------
   Example 5-19 Creating the EMPLOYEES_DS Data Security Policy
-----------------------------------------------------------

declare
      realms   xs$realm_constraint_list := xs$realm_constraint_list();
      cols     xs$column_constraint_list := xs$column_constraint_list();
    begin
      realms.extend(4);
    
      -- Realm #1: Only the order's own record.
      --           SR_ROLE can view the realm including DISCOUNT column.
      realms(1) := xs$realm_constraint_type(
       realm    => 'COMMERCIAL = lower(xs_sys_context(''xs$session'',''username''))',
       acl_list => xs$name_list('sr_acl'));
       
     -- Realm #2: The records in the same region as the Region Manager.
     --           
     realms(2) := xs$realm_constraint_type(
       realm    => 'REGION = &' || 'PREGION'		
       );
    
     -- Realm #3: All the records.
     --           HQ_ROLE can view and update the realm including DISCOUNT column.
     
     realms(3) := xs$realm_constraint_type(
       realm    => '1 = 1',
       acl_list => xs$name_list('hq_acl'));
   --  Realm #4R: All the records.
   --  SA_ROLE can view and update the realm excluding DISCOUNT column.
      realms(4) := xs$realm_constraint_type(
       realm    => '1 = 1',
       acl_list => xs$name_list('sa_acl'));
   
     -- Column constraint protects DISCOUNT column by requiring view_discount
     -- privilege.
     cols.extend(1);
     cols(1) := xs$column_constraint_type(
       column_list => xs$list('DISCOUNT'),
       privilege   => 'view_discount');
   
     sys.xs_data_security.create_policy(
       name                   => 'bio_ds',
       realm_constraint_list  => realms,
       column_constraint_list => cols);
     
     sys.xs_data_security.create_acl_parameter(
                           policy => 'bio_ds',
                           parameter => 'PREGION',
                           param_type => XS_ACL.TYPE_VARCHAR);  
       
   end;
   /
-- ACL for Regions (only Ouest is created)

DECLARE
  ace_list XS$ACE_LIST;
BEGIN
  ace_list := XS$ACE_LIST(
                XS$ACE_TYPE(privilege_list => XS$NAME_LIST('SELECT'),
                            granted => true,
                            principal_name => 'ouest_ventes'),
                XS$ACE_TYPE(privilege_list => XS$NAME_LIST('SELECT', 'view_discount'),
                            granted => true,
                            principal_name => 'ouest_ventes'));
 
  sys.xs_acl.create_acl(name => 'view_ouest_ventes',
                ace_list => ace_list,
                sec_class => 'bioprivs',
                description => 'Authorize read access for the ouest region');
 
  sys.xs_acl.add_acl_parameter(acl => 'view_ouest_ventes',
                           policy => 'bio_ds',
                           parameter => 'PREGION',
                           value => 'ouest');
END;
/  

-- ACLs for other regions have to be done !


------------------------------------------
Validating policy
------------------------------------------
begin
  if (sys.xs_diag.validate_workspace()) then
    dbms_output.put_line('All configurations are correct.');
  else
    dbms_output.put_line('Some configurations are incorrect.');
  end if;
end;
/

-----------------------------------------
Apply the data security policy to the EMPLOYEES table.
------------------------------------------
begin
  xs_data_security.apply_object_policy(
    policy => 'bio_ds', 
    schema => 'DEMO',
    object =>'ADO_PLAN');
end;
/
 -------------------------------------
 CLEAN-UP
 -------------------------------------
 
-- Delete the data security policy.

BEGIN
    sys.xs_data_security.delete_policy('bio_ds', xs_admin_util.cascade_option);
    sys.xs_security_class.delete_security_class('bioprivs',xs_admin_util.cascade_option);
    sys.xs_acl.delete_acl('sr_acl', xs_admin_util.cascade_option);
    sys.xs_acl.delete_acl('rg_acl', xs_admin_util.cascade_option);
    sys.xs_acl.delete_acl('hq_acl', xs_admin_util.cascade_option);
    sys.xs_acl.delete_acl('view_ouest_ventes', xs_admin_util.cascade_option);
    -- delete roles
    -- TBD!
END;
/

----------
-- 'REGION IN (select REGION from DEMO.ADO_EMP where REGION = '||'REGION and -- login = lower(xs_sys_context(''xs$session'',''username'')))
-----------
/* 
Indicateur de confidentialité
(a utiliser dans un decode)
 COLUMN_AUTH_INDICATOR(col)
RETURN BOOLEAN;
*/
-----------------------------
disable Policy
-----------------------------
BEGIN
  SYS.XS_DATA_SECURITY.DISABLE_OBJECT_POLICY(
      policy => 'BIO_DS', 
     schema => 'DEMO', 
    object => 'ADO_PLAN');
END;
/
-----------------------------
tests dynamic roles
-----------------------------

begin xs_principal.create_dynamic_role(name=>'MY_DYN_APP_ROLE'); end;
grant db_emp to MY_DYN_APP_ROLE;
select * from ado_plan where region = 
(select region from ado_emp where job = 'responsable régional' and login = lower(xs_sys_context('xs$session','username')))
 
 --------------------------------------------
 -------------------------------------------
-- Remove Policy
-------------------------------------------

exec sys.xs_data_security.delete_policy('bio_ds', xs_admin_util.cascade_option);

APEX_AUTHORIZATION.RESET_CACHE; ??