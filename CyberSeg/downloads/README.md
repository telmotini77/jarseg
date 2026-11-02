# Descargas del panel

Los archivos de esta carpeta se ofrecen en `https://<IP>/descargas/` a los usuarios que han iniciado sesión.

Para publicar el programa de Windows, compílalo en un PC con Windows y cópialo aquí con el nombre `CyberSeg.exe`:

```powershell
powershell -ExecutionPolicy Bypass -File desktop\build.ps1
scp desktop\dist\CyberSeg.exe usuario@IP-del-servidor:~/CyberSeg/downloads/
```
