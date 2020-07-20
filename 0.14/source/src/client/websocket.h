/* This file is part of openGalaxy.
 *
 * opengalaxy - a SIA receiver for Galaxy security control panels.
 * Copyright (C) 2015 - 2019 Alexander Bruines <alexander.bruines@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * as published by the Free Software Foundation, or (at your option)
 * any later version.
 *
 * In addition, as a special exception, the author of this program
 * gives permission to link the code of its release with the OpenSSL
 * project's "OpenSSL" library (or with modified versions of it that
 * use the same license as the "OpenSSL" library), and distribute the
 * linked executables. You must obey the GNU General Public License
 * in all respects for all of the code used other than "OpenSSL".
 * If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so.
 * If you do not wish to do so, delete this exception statement
 * from your version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __OPENGALAXY_CLIENT_WEBSOCKET_H__
#define __OPENGALAXY_CLIENT_WEBSOCKET_H__

#include <stdbool.h>
#include <gtk/gtk.h>

GThread *WebsocketThreadId;

GThread *Websocket_InitThread( void );
gpointer Websocket_ExitThread( void );

int  Websocket_IsConnected          ( void );
void Websocket_SetConnectParameters ( char *addr, int prt, int ssl, char *auth, char *auth_key, char *ca );
void Websocket_AsyncConnect         ( void );
void Websocket_AsyncDisconnect      ( void );
bool Websocket_SendCommand          ( const char *cmd, ... );
int  Websocket_SendCredentials      ( const char *session_id, const char *username, const char *password );

#endif

