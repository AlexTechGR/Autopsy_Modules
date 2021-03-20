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


class ArtifactGroupFactory(IngestModuleFactoryAdapter):

    moduleName = "CKC - Delivery - Devices Attached"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Finds Devices Attached (CKC - Delivery)"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ArtifactGroup()


class ArtifactGroup(DataSourceIngestModule):

    _logger = Logger.getLogger(ArtifactGroupFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
    def __init__(self):
        self.context = None

    def startUp(self, context):
        self.context = context
    pass

    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Get Devices Attached from blackboard
        skCase = Case.getCurrentCase().getSleuthkitCase()
        artDevicesID = skCase.getArtifactTypeID("TSK_DEVICE_ATTACHED")
        # print it to the log file
        self.log(Level.INFO, "Artifact type ID of TSK_DEVICE_ATTACHED:  " + str(artDevicesID))
        # get all artifacts that have this type ID from the database using the Sleuthkit API - not the database via sql queries
        devicesAttArtifacts = skCase.getBlackboardArtifacts(artDevicesID)
        # print the number of the artifacts in the log file
        self.log(Level.INFO, "Number of TSK_DEVICE_ATTACHED artifacts found:  " + str(len(devicesAttArtifacts)))
        # create new artifact type
        try:
            skCase.addArtifactType("TSK_CKC_DEVICE_ATTACHED", "CKC Delivery Device Attached")
        except:
            # if the artifact type already exists do nothing
            self.log(Level.INFO, "TSK_CKC_DEVICE_ATTACHED artifact already exists")

        # first we need to get the IDs of the TSK_CKC_DEVICE_ATTACHED and of the attributes of the TSK_CKC_DEVICE_ATTACHED
        artID_CKC_DEVICE_ATTACHED = skCase.getArtifactTypeID("TSK_CKC_DEVICE_ATTACHED")
        attID_TSK_DATETIME = skCase.getAttributeType("TSK_DATETIME")
        attID_TSK_DEVICE_MAKE = skCase.getAttributeType("TSK_DEVICE_MAKE")
        attID_TSK_DEVICE_MODEL = skCase.getAttributeType("TSK_DEVICE_MODEL")
        attID_TSK_DEVICE_ID = skCase.getAttributeType("TSK_DEVICE_ID")

        for attDArt in devicesAttArtifacts:
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
                                         attDArt.getAttribute(attID_TSK_DEVICE_ID).getValueString()))
                ))
                try:
                    blackboard.postArtifact(art)
                except:
                    pass
            except:
                self.log(Level.INFO, "Artifact cannot be created. Moved to next.")

        return IngestModule.ProcessResult.OK

    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, ArtifactGroupFactory.moduleName,
            str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)