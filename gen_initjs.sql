create or replace function GEN_INITJS ( p_appid INTEGER, 
                                        p_lovname VARCHAR2)
return VARCHAR2

-- generates the "Initialization JavaScript Function" attribute
-- for a popup lov item in an Oracle APEX application
-- GPM Factory sep 2023 - V1
as
ind integer := 0;
js VARCHAR2(32767);
NL CONSTANT varchar2(10) := chr(13)||chr(10);
itab INTEGER := 0;
    function gtab (i INTEGER) return varchar2 is
        TAB CONSTANT VARCHAR2(100) := chr(9);
        begin
        return LPAD(' ', i,TAB);
    end;

begin
    js := 'function(options) {' ||
    NL|| gtab(2)||'options.defaultGridOptions = {'||NL||
    gtab(3)||'columns: [{' || NL;
    for i in ( select query_column_name, heading, rownum 
                from
                APEX_APPLICATION_LOV_COLS 
                where application_id=p_appid and 
                LIST_OF_VALUES_NAME = p_lovname and
                is_visible = 'Yes'
                order by display_sequence) LOOP
        if ind = 1 then 
            js := gtab(4) || js ||','||NL;
        else
            ind := 1;    
        end if;    
        js := js || gtab(4)|| i.query_column_name || 
        ': {' || NL||   gtab(6) ||'heading: "' || i.heading ||'",'||
                   NL|| gtab(6) ||'width: 300,' ||
                   NL|| gtab(6) ||'alignment: "start",'||
                   NL|| gtab(6) ||'headingAlignment: "start",'||
                   NL|| gtab(6) ||'sortIndex: '||i.rownum ||','||
                   NL|| gtab(6) ||'sortDirection: "desc",'||
                   NL|| gtab(6) ||'canSort: true,'||
                   NL|| gtab(6) ||'noStretch: true'||
                   NL|| gtab(4) || '}' ;   
end loop;    
js := js || NL||gtab(3)||
        '}]'||
    NL||gtab(2) ||'};'||
  NL ||gtab(1)|| 'return options;
}
';
return js;
end GEN_INITJS;
/