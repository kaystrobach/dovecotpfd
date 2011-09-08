<?php

/**
* Dovecot Password File Driver (dovecotpfd)
*
* Roundcube password plugin driver that adds functionality to change passwords stored in
* Dovecot passwd/userdb files (see: http://wiki.dovecot.org/AuthDatabase/PasswdFile)
*
* Copyright (C) 2011, Charlie Orford
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2
* as published by the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.     
*
*
* SCRIPT REQUIREMENTS:
*
*  - PHP 5.3.0 or higher, shell access and the ability to run php scripts from the CLI
*
*  - chgdovecotpw and dovecotpfd-setuid.c (these two files should have been bundled with this driver)
*
*  - dovecotpfd-setuid.c must be compiled and the resulting dovecotpfd-setuid binary placed in the same directory
*    as this script (see dovecotpfd-setuid.c source for compilation instructions, security info and options)
*
*  - chgdovecotpw must be placed in a location where dovecotpfd-setuid can access it once it has changed UID (normally /usr/sbin is a good choice)
*
*  - chgdovecotpw should only be executable by the user dovecotpfd-setuid changes UID to
*
*  - the dovecot passwd/userdb file must be accessible and writable by the same user dovecotpfd-setuid changes UID to
*
*  - dovecotpw (usually packaged with dovecot itself and found in /usr/sbin) must be available and executable by chgdovecotpw
*
*
* @version 1.1 (2011-09-08)
* @author Charlie Orford (charlie.orford@attackplan.net)
**/

function password_save($currpass, $newpass)
{

	$rcmail = rcmail::get_instance();
	$currdir = realpath(dirname(__FILE__));
	list($user, $domain) = explode("@", $_SESSION['username']);
	$username = (rcmail::get_instance()->config->get('password_dovecotpfd_format') == "%n") ? $user : $_SESSION['username'];	
	$scheme = rcmail::get_instance()->config->get('password_dovecotpfd_scheme');
	
	// Set path to dovecot passwd/userdb file
	// (the example below shows how you can support multiple passwd files, one for each domain. If you just use one file, replace sprintf with a simple string of the path to the passwd file)
	$passwdfile = sprintf("/home/mail/%s/passwd", $domain);
	
	// Build command to call dovecotpfd-setuid wrapper
	$exec_cmd = sprintf("%s/dovecotpfd-setuid -f=%s -u=%s -s=%s -p=\"%s\" 2>&1", $currdir, escapeshellcmd(realpath($passwdfile)), escapeshellcmd($username), escapeshellcmd($scheme), escapeshellcmd($newpass));
	
	// Call wrapper to change password
	if ($ph = @popen($exec_cmd, "r"))
	{
		
		$response = "";
		while (!feof($ph))
			$response .= fread($ph, 8192);
		
		if (pclose($ph) == 0)
			return PASSWORD_SUCCESS;

		raise_error(array(
			'code' => 600,
			'type' => 'php',
			'file' => __FILE__, 'line' => __LINE__,
			'message' => "Password plugin: $currdir/dovecotpfd-setuid returned an error"
			), true, false);
		
		return PASSWORD_ERROR;
		
	} else {
	
		raise_error(array(
			'code' => 600,
			'type' => 'php',
			'file' => __FILE__, 'line' => __LINE__,
			'message' => "Password plugin: error calling $currdir/dovecotpfd-setuid"
			), true, false);

		return PASSWORD_ERROR;
		
	}

}

?>
