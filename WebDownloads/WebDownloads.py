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


class ArtifactGroupFactory(IngestModuleFactoryAdapter):

    moduleName = "CKC - Delivery - Web Downloads"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Finds Web Downloads (CKC - Delivery)"

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

        # Find Delivery clues
        # get the sleuthkit database. See org.sleuthkit.datamodel.sleuthkitcase
        # http://sleuthkit.org/sleuthkit/docs/jni-docs/4.10.1/annotated.html
        skCase = Case.getCurrentCase().getSleuthkitCase()
        # get the artifact_type_id of the TSK_WEB_DOWNLOAD artifact type
        artWebDownloadId = skCase.getArtifactTypeID("TSK_WEB_DOWNLOAD")
        # print it to the log file
        self.log(Level.INFO, "Artifact type ID of TSK_WEB_DOWNLOAD:  " + str(artWebDownloadId))
        # get all artifacts that have this type ID from the database using the Sleuthkit API - not the database via sql queries
        webDownloadArtifacts = skCase.getBlackboardArtifacts(artWebDownloadId)
        # print the number of the artifacts in the log file
        self.log(Level.INFO, "Number of TSK_WEB_DOWNLOAD artifacts found:  " + str(len(webDownloadArtifacts)))
        # create new artifact type
        try:
            skCase.addArtifactType("TSK_CKC_WEB_DOWNLOAD", "CKC Delivery Web Downloads")
        except:
            # if the artifact type already exists do nothing
            self.log(Level.INFO, "TSK_CKC_WEB_DOWNLOAD artifact already exists")
        # the attributes of the TSK_CKC_WEB_DOWNLOAD will be the same with those of TSK_WEB_DOWNLOAD
        # so we use them instead of creating new ones

        # first we need to get the IDs of the TSK_CKC_WEB_DOWNLOAD and of the attributes of the TSK_WEB_DOWNLOAD
        artID_CKC_WEB_DOWNLOAD = skCase.getArtifactTypeID("TSK_CKC_WEB_DOWNLOAD")
        attID_TSK_PATH = skCase.getAttributeType("TSK_PATH")
        attID_TSK_URL = skCase.getAttributeType("TSK_URL")
        attID_TSK_DATETIME_ACCESSED = skCase.getAttributeType("TSK_DATETIME_ACCESSED")
        attID_TSK_DOMAIN = skCase.getAttributeType("TSK_DOMAIN")
        attID_TSK_PATH_ID = skCase.getAttributeType("TSK_PATH_ID")
        attID_TSK_PROG_NAME = skCase.getAttributeType("TSK_PROG_NAME")

        # for each TSK_WEB_DOWNLOAD artifact
        for wdArt in webDownloadArtifacts:
            # get the obj_id -> this is the ID of the Source file
            sourceFileID = wdArt.getObjectID()
            # get the actual file using its obj_id
            sourceFile = skCase.getAbstractFileById(sourceFileID)
            # create a TSK_CKC_WEB_DOWNLOAD blackboard artifact based on this TSK_WEB_DOWNLOAD
            try:
                art = sourceFile.newArtifact(artID_CKC_WEB_DOWNLOAD)
                art.addAttributes((
                    (BlackboardAttribute(attID_TSK_PATH, ArtifactGroupFactory.moduleName,
                                         wdArt.getAttribute(attID_TSK_PATH).getValueString())), \
                    (BlackboardAttribute(attID_TSK_URL, ArtifactGroupFactory.moduleName,
                                         wdArt.getAttribute(attID_TSK_URL).getValueString())), \
                    (BlackboardAttribute(attID_TSK_DATETIME_ACCESSED, ArtifactGroupFactory.moduleName,
                                         wdArt.getAttribute(attID_TSK_DATETIME_ACCESSED).getValueLong())), \
                    (BlackboardAttribute(attID_TSK_DOMAIN, ArtifactGroupFactory.moduleName,
                                         wdArt.getAttribute(attID_TSK_DOMAIN).getValueString())), \
                    (BlackboardAttribute(attID_TSK_PROG_NAME, ArtifactGroupFactory.moduleName,
                                         wdArt.getAttribute(attID_TSK_PROG_NAME).getValueString())), \
                    (BlackboardAttribute(attID_TSK_PATH_ID, ArtifactGroupFactory.moduleName,
                                         wdArt.getAttribute(attID_TSK_PATH_ID).getValueLong()))
                ))
            except:
                self.log(Level.INFO, "Artifact cannot be created. Moved to next.")

        return IngestModule.ProcessResult.OK

    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, ArtifactGroupFactory.moduleName,
            str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)