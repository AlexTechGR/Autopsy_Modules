# Simple file-level ingest module for Autopsy.
# Search for TODO for the things that you need to change
# See http://sleuthkit.org/autopsy/docs/api-docs/4.6.0/index.html for documentation

import jarray
import inspect
import os
import subprocess
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
# TODO: Rename this to something more specific.  Search and replace for it because it is used a few times
class ArtifactGroupFactory(IngestModuleFactoryAdapter):

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Artifact group (CKC)"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Groups artifacts by CKC phase"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ArtifactGroup()



# File-level ingest module.  One gets created per thread.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class ArtifactGroup(DataSourceIngestModule):

    _logger = Logger.getLogger(ArtifactGroupFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/4.6.0/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        self.context = context
    pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/4.6.0/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Use blackboard class to index blackboard artifacts for keyword search
        case = Case.getCurrentCase().getSleuthkitCase()
        self.log(Level.INFO, "Case Name: " + str(case))
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()

        # Find Reconnaissance clues
        files = []
        files = fileManager.findFiles(dataSource, "%.log")
        files += fileManager.findFiles(dataSource, "%.evt")
        files += fileManager.findFiles(dataSource, "%.evtx")
        files += fileManager.findFiles(dataSource, "%.pcap")

        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

        for file in files:
            fileCount += 1
            self.log(Level.INFO, "++++++Processing file: " + file.getName())
            self.log(Level.INFO, "File count:" + str(fileCount))
            # Make an artifact on the blackboard.  TSK_INTERESTING_FILE_HIT is a generic type of
            # artifact.  Refer to the developer docs for other examples.
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                                      ArtifactGroupFactory.moduleName, "Reconnaissance")
            art.addAttribute(att)
            try:
                # index the artifact for keyword search
                blackboard.indexArtifact(art)
            except Blackboard.BlackboardException as e:
                self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

            # Fire an event to notify the UI and others that there is a new artifact
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(ArtifactGroupFactory.moduleName,
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None))

        # Find Weaponization  clues
        # dont even know what to look for
        files = []

        # Find Delivery clues
        files = []
        files = fileManager.findFiles(dataSource, "%", "%/Users/%/Downloads/")
        files += fileManager.findFiles(dataSource, "%", "%USERPROFILE%\AppData\Local\Microsoft\Credentials")
        files += fileManager.findFiles(dataSource, "%", "%USERPROFILE%\AppData\Roaming\Skype\<skype-name>")
        files += fileManager.findFiles(dataSource, "%", "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\IEDownloadHistory\index.dat")
        files += fileManager.findFiles(dataSource, "%", "%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat")
        files += fileManager.findFiles(dataSource, "%", "%userprofile%\AppData\Roaming\Mozilla\ Firefox\Profiles\<random text>.default\downloads.sqlite")
        files += fileManager.findFiles(dataSource, "%", "%userprofile%\AppData\Roaming\Mozilla\ Firefox\Profiles\<random text>.default\places.sqlite")
        files += fileManager.findFiles(dataSource, "%", "%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\History")

        for file in files:
            fileCount += 1
            self.log(Level.INFO, "++++++Processing file: " + file.getName())
            self.log(Level.INFO, "File count:" + str(fileCount))
            # Make an artifact on the blackboard.  TSK_INTERESTING_FILE_HIT is a generic type of
            # artifact.  Refer to the developer docs for other examples.
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                                      ArtifactGroupFactory.moduleName, "Delivery")
            art.addAttribute(att)
            try:
                # index the artifact for keyword search
                blackboard.indexArtifact(art)
            except Blackboard.BlackboardException as e:
                self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

            # Fire an event to notify the UI and others that there is a new artifact
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(ArtifactGroupFactory.moduleName,
                                BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None))
        #if file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.TSK_WEB_DOWNLOAD :

        # Find Exploitation   clues
        #files = []

        # Find Installation   clues
        #files = []

        # Find Command and Control  clues
        #files = []

        # Find Actions on Objective  clues
        #files = []




        return IngestModule.ProcessResult.OK

    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, ArtifactGroupFactory.moduleName,
                str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)