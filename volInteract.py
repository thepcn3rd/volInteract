#!/usr/bin/python

from threading import Thread
import cmd, time, os, sys
import ConfigParser
import subprocess

config = ConfigParser.ConfigParser()
config.read("config.ini")
VOLATILITY_LOCATION = config.get('volatility', 'volatility_location')
VOLATILITY_PROFILE = config.get('volatility', 'volatility_profile')
SAVE_LOCATION = config.get('volatility', 'project_save_location')

# Create the output directory if it does not exist
# Verify the Volatility Path - Add to config.ini
# Add volatility path to the options that can be setup

# Break-out the directories into stages of the checklist
# Integrate foremost into the tool...
# Integrate MFT analysis into the tool...

vPATH = "/usr/bin/vol.py"  # Volatility PATH

def pluginExec(c):
	global VOLATILITY_LOCATION, VOLATILITY_PROFILE, config, SAVE_LOCATION, vPATH
	commandStr = ""
	if c == "malfind":
		if not os.path.exists("output/malfind-dump"):
			os.makedirs("output/malfind-dump")
			commandStr = vPATH + " -f " + VOLATILITY_LOCATION + " " + c + " --output-file=output/" + c + ".txt --dump-dir=output/malfind-dump"
			# Save to a text file the processes that are unique in the malfind.txt output
			commandStr += ";cat output/malfind.txt | grep 'Process:' | awk '{print $1 \" \" $2 \" \" $3 \" \" $4}' | sort | uniq -c | sort -n > output/malfind-unique-processes.txt"
			# Save a clamscan of the malfind-dump directory to the output folder
			commandStr += ";clamscan output/malfind-dump/ --log=output/malfind-clamscan-results.txt --quiet"
			print "Executing: " + commandStr
		else:
			print "Appears the directory of malfind-dump already exists in the output.  Remove before running again..."
	else:
		commandStr = vPATH + " -f " + VOLATILITY_LOCATION + " --profile=" + VOLATILITY_PROFILE + " " + c + " --output-file=output/" + c + ".txt"
	try:
		print "Running in the background... Run 'show output' to see if the file was created."
		print "Execute 'cat <filename>' to read the contents of the output file."
		print "Executing: " + commandStr
		subprocess.Popen([commandStr], shell=True)
	except:
		print "Error executing command: " + commandStr
		print
	print
	return

class volInteractive(cmd.Cmd):
	def __init__(self):
		global VOLATILITY_LOCATION, VOLATILITY_PROFILE
		print
		print "Volatility Workspace"
		print "--------------------"
		print "Volatility Image Location: " + VOLATILITY_LOCATION
		print "Volatility Profile Selected: " + VOLATILITY_PROFILE
		print "Project Directory: " + SAVE_LOCATION
		selection = raw_input("Do you need to update the above options? ")
		if selection == 'Y' or selection == 'y':
			print "set location - Set the VOLATILITY_LOCATION in the config.ini"
			print "set profile - Set the VOLATILITY_PROFILE in the config.ini"
			print "set save - Set where teh Project files are saved"
			print
		print
		print "Output Gathered"
		print "---------------"
		os.system("ls -l output")
		print
		if not os.path.exists("output"):
			os.makedirs("output")
		cmd.Cmd.__init__(self)
		time.sleep(2)
		self.prompt = "#> "
		return

	def do_show(self, command):
		"""Show the settings that are configured"""
		global VOLATILITY_LOCATION, VOLATILITY_PROFILE, SAVE_LOCATION
		if command == "all":
			print "Volatility Image Location: " + VOLATILITY_LOCATION
			print "Volatility Profile Selected: " + VOLATILITY_PROFILE
			print "Project Directory: " + SAVE_LOCATION
			print
		elif command == "location":
			print "Volatility Image Location: " + VOLATILITY_LOCATION
			print
		elif command == "output":
			os.system("ls -l output/")
			print
		elif command == "profile":	
			print "Volatility Profile Selected: " + VOLATILITY_PROFILE
			print
		elif command == "save":
			print "Project Directory: " + SAVE_LOCATION
		else:
			print "show all - Show all of the settings configured"
			print "show location - Show the VOLATILITY_LOCATION selected"
			print "show output - Show the contents of the output directory"
			print "show profile - Show the VOLATILITY_PROFILE selected" 
			print "show save - Show where the Project files are saved"
			print
		return

	def do_output(self, command):
		"""Show the contents of the output directory"""
		os.system("ls -l output/")
		print
		return

	def do_use(self, command):
		"""Use the specified plugin"""
		if command == "psscan" or command == "pslist" or command == "pstree" or command == "psxview":
			pluginExec(command)
		elif command == "autoruns":
			pluginExec(command)
		elif command == "consoles" or command == "cmdscan" or command == "connections" or command == "connscan":
			pluginExec(command)
		elif command == "imageinfo":
			pluginExec(command)
		elif command == "malfind":
			pluginExec(command)
		elif command == "clamscan":
			commandStr = "clamscan output/ --log=output/clamscan.txt --quiet"
			print "Executing: " + commandStr
			subprocess.Popen([commandStr], shell=True)
		elif command == "sockets" or command == "sockscan" or command == "svcscan":
			pluginExec(command)
		else:
			print "use autoruns - Searches the registry and memory space for applications running at system startup and maps them to running processes"
			print "use clamscan - Executes a recursive scan on the output folder"
			print "use cmdscan - Extract command history by scanning for _COMMAND_HISTORY"
			print "use connections - Print list of open connections [Windows XP and 2003 Only]"
			print "use connscan - Pool scanner for tcp connections"
			print "use consoles - Extract command history by scanning for _CONSOLE_INFORMATION"
			print "use imageinfo - Executes the imageinfo plugin"
			print "use malfind - Find hidden and injected code"
			print "use pslist - Print all running processes by following the EPROCESS lists"
			print "use psscan - Executes the psscan plugin in the background"
			print "use psxview - Find hidden processes with various process listings"
			print "use pstree -  Print process list as a tree"
			print "use sockets - Print list of open sockets"
			print "use sockscan - Pool scanner for tcp socket objects"
			print "use svcscan -  Scan for Windows services"
			#print "use pstotal - Combination of pslist,psscan & pstree
			print
		return

	def do_pwd(self, command):
		"""Displays the present working directory"""
		os.system("pwd")
		print
		return

	def do_ls(self, command):
		"""Displays a directory listing of the pwd or specified directory of output or directories in output"""
		items = command.split(" ")
		if items[0] <> '':
			if items[0] == "output":
				os.system("ls -l output/")
			elif items[0] == "malfind-dump":
				os.system("ls -l output/malfind-dump/")
		else:
			"""Displays the content of the current directory."""
			os.system("ls -l")
			print
		return

	def do_cat(self, command):
		"""cat a particular file in the output directory"""
		command = command.replace(" ","")
		command = command.replace(";","")
		systemCmd = "cat output/" + command
		os.system(systemCmd)
		print 
		return

	def do_search(self, command):
		"""Search for a keyword in the files in the output directory.  Does not include the sub-directories"""
		command = command.replace(" ","")
		command = command.replace(";","")
		command = command.strip()
		if not command == "":
			systemCmd = "grep -i " + command + " output/*.txt"
			os.system(systemCmd)
		print
		return	

	def do_clamscan(self, command):
		"""Run a recursive clamscan on files in the output directory"""
		commandStr = "clamscan output/ --log=output/clamscan.txt --quiet"
		print "Executing: " + commandStr
		subprocess.Popen([commandStr], shell=True)
		return	

	def do_note(self, command):
		"""Creates a note and appends it to output/notes.txt"""
		txtNote = raw_input("Note: ")
		f = open('output/notes.txt', 'a')
		txtNote = txtNote + '\n'
		f.write(txtNote)
		f.close()
		print
		return

	def do_set(self, command):
		"""Set and save Global Variables to config.ini""" 
		global VOLATILITY_LOCATION, VOLATILITY_PROFILE, config, SAVE_LOCATION
		if command == "location":
			newLocation = raw_input("New Image Location: ")
			newLocation = newLocation.strip()
			config.set('volatility','volatility_location', newLocation)
			with open('config.ini', 'wb') as configfile:
				config.write(configfile)
			VOLATILITY_LOCATION = config.get('volatility', 'volatility_location')
			print
		elif command == "profile":
			newProfile = raw_input("New Image Profile: ")
			newProfile = newProfile.strip()
			config.set('volatility','volatility_profile', newProfile)
			with open('config.ini', 'wb') as configfile:
				config.write(configfile)
			VOLATILITY_PROFILE = config.get('volatility', 'volatility_profile')
			print
		elif command == "save":
			newSave = raw_input("New Project Directory (ie. /home/user2/project1): ")
			newSave = newSave.strip()
			config.set('volatility','project_save_location', newSave)
			with open('config.ini', 'wb') as configfile:
				config.write(configfile)
			SAVE_LOCATION = config.get('volatility', 'project_save_location')
			print
		else:
			print "set location - Set the VOLATILITY_LOCATION in the config.ini"
			print "set profile - Set the VOLATILITY_PROFILE in the config.ini"
			print "set save - Set where teh Project files are saved"
			print
		return		

	def do_checklist(self, command):
		"""Outputs the Best Practice Checklist of Malware Analysis based on Information Collected"""
		### Stage 1
		print "Stage 1: Identify Rogue Processes"
		if os.path.exists("output/pslist.txt"): 
			print "[X] pslist - Print all running processes within the EPROCESS doubly linked list"
		else:
			print "[ ] pslist - Print all running processes within the EPROCESS doubly linked list"
		if os.path.exists("output/psscan.txt"):
			print "[X] psscan - Scan physical memory for EPROCESS pool allocations"
		else:
			print "[ ] psscan - Scan physical memory for EPROCESS pool allocations"
		if os.path.exists("output/pstree.txt"):
			print "[X] pstree - Print Process list as a tree showing parent relationships using EPROCESS linked list"
		else:
			print "[ ] pstree - Print Process list as a tree showing parent relationships using EPROCESS linked list"
		if os.path.exists("output/pstotal.txt"):
			print "[X] pstotal - Comparison of psscan and pslist results.  Also produces output in graphics format"
		else:
			print "[ ] pstotal - Comparison of psscan and pslist results.  Also produces output in graphics format"
		if os.path.exists("output/malsysproc.txt"):
			print "[X] malsysproc - Identify suspicious system processes"
		else:
			print "[ ] malsysproc - Identify suspicious system processes"
		if os.path.exists("output/processbl.txt"):
			print "[X] processbl - Compares processes and loaded DLLs with a Baseline Image"
		else:
			print "[ ] processbl - Compares processes and loaded DLLs with a Baseline Image"
		### Stage 2
		print
		print "Stage 2: Analyze Process Objects"
		if os.path.exists("output/dlllist.txt"):
			print "[X] dlllist - Print list of loaded dlls for each process"
		else:	
			print "[ ] dlllist - Print list of loaded dlls for each process"
		if os.path.exists("output/cmdline.txt"):
			print "[X] cmdline - Display command-line args for each process"
		else:
			print "[ ] cmdline - Display command-line args for each process"
		if os.path.exists("output/cmdscan.txt"):
			print "[X] cmdscan - Extract command history by scanning for _COMMAND_HISTORY"
		else:
			print "[ ] cmdscan - Extract command history by scanning for _COMMAND_HISTORY"
		if os.path.exists("output/getsids.txt"):
			print "[X] getsids - Print process security identifiers"
		else:
			print "[ ] getsids - Print process security identifiers"
		if os.path.exists("output/handles.txt"):
			print "[X] handles - List of open handles for each process"
		else:
			print "[ ] handles - List of open handles for each process"
		if os.path.exists("output/filescan.txt"):
			print "[X] filescan - Scan memory for FILE_OBJECT handles"
		else:
			print "[ ] filescan - Scan memory for FILE_OBJECT handles"
		if os.path.exists("output/svcscan.txt"):
			print "[X] svcscan - Scan for Windows Service Information"
		else:
			print "[ ] svcscan - Scan for Windows Service Information"
		if os.path.exists("output/autoruns.txt"):
			print "[X] autoruns - Searches the registry and memory locations running at system startup and maps them to running processes"
		else:
			print "[ ] autoruns - Searches the registry and memory locations running at system startup and maps them to running processes"
		### Stage 3
		print 
		print "Stage 3: Review Network Artifacts"
		if os.path.exists("output/connections.txt"):
			print "[X] connections - List of Open TCP Connections [XP]"
		else:
			print "[ ] connections - List of Open TCP Connections [XP]"
		if os.path.exists("output/connscan.txt"):
			print "[X] connscan - TCP Connections including closed [XP]"
		else:
			print "[ ] connscan - TCP Connections including closed [XP]"
		if os.path.exists("output/sockets.txt"):
			print "[X] sockets - Print Listening Sockets (any protocol)"
		else:
			print "[ ] sockets - Print Listening Sockets (any protocol)"
		if os.path.exists("output/sockscan.txt"):
			print "[X] sockscan - ID sockets, including closed and unlinked"
		else:
			print "[ ] sockscan - ID sockets, including closed and unlinked"
		if os.path.exists("output/netscan.txt"):
			print "[X] netscan - Scan for connections and sockets"
		else:
			print "[ ] netscan - Scan for connections and sockets"
		### Stage 4
		print
		print "Stage 4: Look for Evidence of Code Injection"
		if os.path.exists("output/malfind.txt"):
			print "[X] malfind - Find injected code and dump sections"
		else:
			print "[ ] malfind - Find injected code and dump sections"
		if os.path.exists("output/ldrmodules.txt"):
			print "[X] ldrmodules - Detect unlinked DLLs"
		else:
			print "[ ] ldrmodules - Detect unlinked DLLs"
		### Stage 5
		print
		print "Stage 5: Check for Signs of a Rootkit"
		if os.path.exists("output/psxview.txt"):
			print "[X] psxview - Find hidden processes using cross-view"
		else:
			print "[ ] psxview - Find hidden processes using cross-view"
		if os.path.exists("output/modscan.txt"):
			print "[X] modscan - Scan memory for loaded, unloaded and unlinked drivers"
		else:
			print "[ ] modscan - Scan memory for loaded, unloaded and unlinked drivers"
		if os.path.exists("output/apihooks.txt"):
			print "[X] apihooks - Find API/DLL function hooks"
		else:
			print "[ ] apihooks - Find API/DLL function hooks"
		if os.path.exists("output/ssdt.txt"):
			print "[X] ssdt - Hooks in System Service Descriptor Table"
		else:
			print "[ ] ssdt - Hooks in System Service Descriptor Table"
		if os.path.exists("output/driverirp.txt"):
			print "[X] driverirp - Identify I/O Request Packet Hooks"
		else:
			print "[ ] driverirp - Identify I/O Request Packet Hooks"
		if os.path.exists("output/idt.txt"):
			print "[X] idt - Display Interrupt Descriptor Table"
		else:
			print "[ ] idt - Display Interrupt Descriptor Table"
		### Stage 6
		print
		print "Stage 6: Dump Suspicious Processes and Drivers"
		if os.path.exists("output/dlldump.txt"):
			print "[X] dlldump - Extract DLLs from Specific Processes"
		else:
			print "[ ] dlldump - Extract DLLs from Specific Processes"
		if os.path.exists("output/moddump.txt"):
			print "[X] moddump - Extract Kernel Drivers"
		else:
			print "[ ] moddump - Extract Kernel Drivers"
		if os.path.exists("output/procmemdump.txt"):
			print "[X] procmemdump - Dump process to executable sample"
		else:
			print "[ ] procmemdump - Dump process to executable sample"
		if os.path.exists("output/memdump.txt"):
			print "[X] memdump - Dump every memory section into a file"
		else:
			print "[ ] memdump - Dump every memory section into a file"
		return


	def emptyline(self):
		pass
		return

	def do_exit(self, line):
		"""Exit the Volatility Workspace"""
		return True




if __name__ == '__main__':
	vI = volInteractive()
	t1 = Thread(target = vI.cmdloop)
	t1.start()
	t1.join()
