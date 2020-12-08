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


        # get the sleuthkit database - it contains all artifacts of the blackboard
        skCase = Case.getCurrentCase().getSleuthkitCase()
        # create the fileManager
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        # get the type ID of the TSK_WEB_DOWNLOAD artifacts
        artWebDownloadId = skCase.getArtifactTypeID("TSK_WEB_DOWNLOAD")
        # print it to the log file
        self.log(Level.INFO, "Artifact type Id of TSK_WEB_DOWNLOAD:  " + str(artWebDownloadId) )
        # get all artifacts that have this type ID from the skCase - i.e., from the database
        webDownloadArtifacts = skCase.getBlackboardArtifacts(artWebDownloadId)
        # print the number of the artifacts in the log file
        self.log(Level.INFO, "Number of TSK_WEB_DOWNLOAD artifacts found :  " + str(len(webDownloadArtifacts)) )
        # create new artifact type
        try:
            artID_CKC_WEB_DOWNLOAD = skCase.addArtifactType("TSK_CKC_WEB_DOWNLOAD", "CKC Delivery Web Downloads")
        except:
            self.log(Level.INFO, "TSK_CKC_WEB_DOWNLOAD artifact already exists")
        # create the atributes of the artID_CKC_WEB_DOWNLOAD
        # see below how I retrieved the atributes of the TSK_WEB_DOWNLOAD
        try:
            attID_ckc_web_download_path = skCase.addArtifactAttributeType("TSK_CKC_WEB_DOWNLOAD_PATH",
                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                      "Path where the file is downloaded")
        except:
            self.log(Level.INFO, "TSK_CKC_WEB_DOWNLOAD_PATH attribute already exists")
        try:
            attID_ckc_web_download_pathID = skCase.addArtifactAttributeType("TSK_CKC_WEB_DOWNLOAD_PATHID",
                                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                      "The path ID")
        except:
            self.log(Level.INFO, "TSK_CKC_WEB_DOWNLOAD_PATHID attribute already exists")
        try:
            attID_ckc_web_download_URL = skCase.addArtifactAttributeType("TSK_CKC_WEB_DOWNLOAD_URL",
                                                                        BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                        "URL used to download the file")
        except:
            self.log(Level.INFO, "TSK_CKC_WEB_DOWNLOAD_URL attribute already exists")
        try:
            attID_ckc_web_download_date = skCase.addArtifactAttributeType("TSK_CKC_WEB_DOWNLOAD_DATE",
                                                                     BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                     "Date Accessed used to download the file")
        except:
            self.log(Level.INFO, "TSK_CKC_WEB_DOWNLOAD_DATE attribute already exists")
        try:
            attID_ckc_web_download_domain = skCase.addArtifactAttributeType("TSK_CKC_WEB_DOWNLOAD_DOMAIN",
                                                                        BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                        "Domain correspond to the URL")
        except:
            self.log(Level.INFO, "TSK_CKC_WEB_DOWNLOAD_DOMAIN attribute already exists")
        try:
            attID_ckc_web_download_program = skCase.addArtifactAttributeType("TSK_CKC_WEB_DOWNLOAD_PROGRAM",
                                                                        BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                                        "Program used to download the file")
        except:
            self.log(Level.INFO, "TSK_CKC_WEB_DOWNLOAD_PROGRAM attribute already exists")

        for eachWebDownload in webDownloadArtifacts:
            artAttributes = eachWebDownload.getAttributes()
            # the attributes are Path, Path ID, URL, Date Accessed, Domain, Program Name
            # uncomment the next 3 lines in case you want to have them printed in the log file
            for attribute in artAttributes:
                self.log(Level.INFO, "Attribute Name :  " + attribute.getAttributeTypeDisplayName() )
                # self.log(Level.INFO, "Attribute Value :  " + attribute.getValueString())

            # at this point we have to find each file that the TSK_WEB_DOWNLOAD refers to
            # this is an important step to create an artifact based on the file using the method file.newArtifact
            # Each file is the file under the Source File column in the Autopsy. The Source file column is the file
            # by which the autopsy creates a new artifact. All next columns are the attributes of the artifact-file

            #Please continue it from here.....
        #     ......

        return IngestModule.ProcessResult.OK

    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, ArtifactGroupFactory.moduleName,
                str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)