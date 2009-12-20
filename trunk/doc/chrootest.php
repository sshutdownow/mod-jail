<?php
#
# $Id$
#

chdir('/');
echo "Current dir is `", getcwd(), "'<br />";

$dir_handle = @opendir('.') or die("Unable to open current dir");
while ($file = readdir($dir_handle)) 
{
   echo "$file<br/>";
}
closedir($dir_handle);

?>
