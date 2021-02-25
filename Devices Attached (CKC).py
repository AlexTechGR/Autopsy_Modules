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
    moduleName = "Devices Attached (CKC)"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Finds Devices Attached (CKC)"

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
        artDevicesAttID = skCase.getArtifactTypeID("TSK_DEVICE_ATTACHED")
        # print it to the log file
        self.log(Level.INFO, "Artifact type ID of TSK_DEVICE_ATTACHED:  " + str(artDevicesAttID))
        # get all artifacts that have this type ID from the database using the Sleuthkit API - not the database via sql queries
        artDevicesAttArtifacts = skCase.getBlackboardArtifacts(artDevicesAttID)
        # print the number of the artifacts in the log file
        self.log(Level.INFO, "Number of TSK_DEVICE_ATTACHED artifacts found:  " + str(len(artDevicesAttArtifacts)))
        # create new artifact type
        try:
            skCase.addArtifactType("TSK_CKC_DEVICE_ATTACHED", "CKC Delivery Device Attached")
        except:
            # if the artifact type already exists do nothing
            self.log(Level.INFO, "TSK_CKC_DEVICE_ATTACHED artifact already exists")

        # first we need to get the IDs of the TSK_CKC_DEVICE_ATTACHED and of the attributes of the TSK_WEB_DOWNLOAD
        artID_CKC_DEVICE_ATTACHED = skCase.getArtifactTypeID("TSK_CKC_DEVICE_ATTACHED")
        attID_TSK_DATETIME = skCase.getAttributeType("TSK_DATETIME")
        attID_TSK_DEVICE_MAKE = skCase.getAttributeType("TSK_DEVICE_MAKE")
        attID_TSK_DEVICE_MODEL = skCase.getAttributeType("TSK_DEVICE_MODEL")
        attID_TSK_DEVICE_ID = skCase.getAttributeType("TSK_DEVICE_ID")
        attID_TSK_PATH_ID = skCase.getAttributeType("TSK_PATH_ID")

        for attDArt in artDevicesAttArtifacts:
            # get the obj_id -> this is the ID of the Source file
            sourceFileID = attDArt.getObjectID()
            # get the actual file using its obj_id
            sourceFile = skCase.getAbstractFileById(sourceFileID)
            # create a TSK_CKC_WEB_DOWNLOAD blackboard artifact based on this TSK_WEB_DOWNLOAD
            try:
                art = sourceFile.newArtifact(artID_CKC_DEVICE_ATTACHED)
                art.addAttributes((
                    (BlackboardAttribute(attID_TSK_DATETIME, ArtifactGroupFactory.moduleName,
                                         attDArt.getAttribute(attID_TSK_DATETIME).getValueLong())), \
                    (BlackboardAttribute(attID_TSK_DEVICE_MAKE, ArtifactGroupFactory.moduleName,
                                         attDArt.getAttribute(attID_TSK_DEVICE_MAKE).getValueString())), \
                    (BlackboardAttribute(attID_TSK_DEVICE_MODEL, ArtifactGroupFactory.moduleName,
                                         attDArt.getAttribute(attID_TSK_DEVICE_MODEL).getValueString())), \
                    (BlackboardAttribute(attID_TSK_DEVICE_ID, ArtifactGroupFactory.moduleName,
                                         attDArt.getAttribute(attID_TSK_DEVICE_ID).getValueString())), \
                    (BlackboardAttribute(attID_TSK_PATH_ID, ArtifactGroupFactory.moduleName,
                                         attDArt.getAttribute(attID_TSK_PATH_ID).getValueLong()))
                ))
            except:
                self.log(Level.INFO, "Artifact cannot be created. Moved to next.")

        dbConn.close()
        return IngestModule.ProcessResult.OK

    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, ArtifactGroupFactory.moduleName,
            str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)