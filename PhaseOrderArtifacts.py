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


        # get the sleuthkit database - it contains all artifacts of the blackboard
        skCase = Case.getCurrentCase().getSleuthkitCase()
        # create the fileManager
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        self.log(Level.INFO, "Case Name: " + str(skCase))

        # # Find Reconnaissance clues
        # id = skCase.getArtifactTypeID("TSK_EVTX_LOGS")
        # id2 = skCase.getArtifactTypeID("TSK_EVTX_LOGS_LONG")
        # artifactList = skCase.getBlackboardArtifacts(id)
        # artifactList += skCase.getBlackboardArtifacts(id2)
        # #artifactList += case.getBlackboardArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_EVTX_LOGS_LONG)
        # for artifact in artifactList:
        #     # self.log(Level.INFO, "test1")
        #     id = artifact.getObjectID()
        #     file = skCase.getAbstractFileById(id)
        #     art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
        #     att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
        #                               ArtifactGroupFactory.moduleName, "Reconnaissance")
        #     art.addAttribute(att)


        # Find Delivery clues
        # get the sleuthkit database. See org.sleuthkit.datamodel.sleuthkitcase
        # http://sleuthkit.org/sleuthkit/docs/jni-docs/4.10.1/annotated.html
        skCase = Case.getCurrentCase().getSleuthkitCase()
        # create the fileManager
        fileManager = Case.getCurrentCase().getServices().getFileManager()
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

