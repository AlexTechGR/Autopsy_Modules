#imports for evtx
from java.lang import Class
from java.lang import System
from java.sql import DriverManager, SQLException
from java.util.logging import Level
from java.io import File

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
    moduleName = "File Attachments Opened (CKC)"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Finds attachments that were opened (CKC)"

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

        # Get Devices Attached from blackboard ////////////////////////
        skCase = Case.getCurrentCase().getSleuthkitCase()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%", "Users/%/AppData/%/Microsoft/Outlook/")

        # create new artifact type
        try:
            skCase.addArtifactType("TSK_CKC_ATTACHMENTS_OPENED", "CKC Delivery File Attachments Opened")
        except:
            # if the artifact type already exists do nothing
            self.log(Level.INFO, "TSK_CKC_ATTACHMENTS_OPENED artifact already exists")
        try:
            attID_dateCreated = skCase.addArtifactAttributeType("TSK_CKC_DATE_CREATED",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME,
                                                          "Date Created")
        except:
            self.log(Level.INFO, "Attributes Creation Error, Event Log File Name. ==> ")
        try:
            attID_dateModified = skCase.addArtifactAttributeType("TSK_CKC_DATE_MODIFIED",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME,
                                                          "Date Modified")
        except:
            self.log(Level.INFO, "Attributes Creation Error, Event Log File Name. ==> ")

        artId = skCase.getArtifactTypeID("TSK_CKC_ATTACHMENTS_OPENED")
        attID_dateCreated = skCase.getAttributeType("TSK_CKC_DATE_CREATED")
        attID_dateModified = skCase.getAttributeType("TSK_CKC_DATE_MODIFIED")

        for file in files:
            self.log(Level.INFO, str(file.getNameExtension()))
            try:
                if file.getNameExtension() != "":
                    art = file.newArtifact(artId)
                    dateCreated = file.getCrtimeAsDate()
                    dateModified = file.getMtimeAsDate()
                    self.log(Level.INFO, str(dateCreated))
                    art.addAttribute()
                    art.addAttributes(
                        ((BlackboardAttribute(attID_dateCreated, ParseEvtxDbIngestModuleFactory.moduleName, dateCreated)), \
                         (BlackboardAttribute(attID_dateModified, ParseEvtxDbIngestModuleFactory.moduleName, dateModified))))
            except:
                self.log(Level.INFO, "Artifact cannot be created. Moved to next.")

        return IngestModule.ProcessResult.OK

    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, ArtifactGroupFactory.moduleName,
            str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)